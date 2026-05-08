#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>   /* shm_unlink */
#include <sys/socket.h>   /* sendto, AF_UNIX, SOCK_DGRAM */
#include <sys/un.h>       /* sockaddr_un */
#include <errno.h>
#include "perf_counter.h"
#include "ebpf_tracer.h"
#include "sliding_window.h"
#include "ring_buffer.h"
#include "smoothed_metrics.h"
#include "proc_scanner.h"
#include "monitor_final.h"
#include <unistd.h>   /* sysconf */

/* FIX 7: build provenance — injected by Makefile via -D flags.
 * Fallbacks ensure the code compiles even when built outside of make
 * (e.g. direct gcc invocation during debugging). */
#ifndef BUILD_DATE
#  define BUILD_DATE "unknown"
#endif
#ifndef GIT_HASH
#  define GIT_HASH   "unknown"
#endif

/* ── Logging macros ─────────────────────────────────────────────────────────
 * Three levels, each respecting the runtime mode flags:
 *
 * LOG_INFO  — normal operational messages ("ring buffers ready", heartbeat,
 *             shutdown summary).  Suppressed by --quiet.  Goes to stdout in
 *             --terminal mode, stderr (→ journal) otherwise.
 *
 * LOG_ERROR — always written to stderr regardless of any mode flag.  Used
 *             for warnings, drops, and fatal error messages.
 *
 * LOG_DEBUG — interactive debugging output (table header, per-PID rows,
 *             separator lines).  Only emitted in --terminal mode; always
 *             suppressed in service/daemon mode regardless of --quiet.
 *
 * Using macros rather than a function keeps call-site line numbers in the
 * output and avoids a varargs wrapper with its associated code-size cost. */
#define LOG_INFO(fmt, ...)  do {                                        \
    if (!g_cfg.quiet_mode)                                              \
        fprintf(g_cfg.terminal_mode ? stdout : stderr,                 \
                fmt, ##__VA_ARGS__);                                    \
} while (0)
#define LOG_ERROR(fmt, ...) do {                                        \
    fprintf(stderr, fmt, ##__VA_ARGS__);                               \
} while (0)
#define LOG_DEBUG(fmt, ...) do {                                        \
    if (g_cfg.terminal_mode && !g_cfg.quiet_mode)                      \
        fprintf(stdout, fmt, ##__VA_ARGS__);                           \
} while (0)

#define MAX_CORES 64  /* max CPU cores supported in per-core mode */

static DaemonConfig   g_cfg;
static PidState       g_states [MAX_PIDS];
static SlidingWindow  g_win_ipc[MAX_PIDS];
static SlidingWindow  g_win_llc[MAX_PIDS];
static SlidingWindow  g_win_ctx[MAX_PIDS];
static SlidingWindow  g_win_io [MAX_PIDS];  /* block I/O completions/sec */
static perf_counter_t g_perf  [MAX_PIDS];           /* aggregate counters */
static perf_counter_t g_perf_pc[MAX_PIDS][MAX_CORES];/* per-core counters */
static SlidingWindow  g_win_ipc_pc[MAX_PIDS][MAX_CORES];
static SlidingWindow  g_win_llc_pc[MAX_PIDS][MAX_CORES];

/* Per-core previous counter snapshots (fix: perf_counter_t has no prev_* fields) */
typedef struct {
    uint64_t prev_cycles;
    uint64_t prev_instr;
    uint64_t prev_llc;
} CorePrev;
static CorePrev g_core_prev[MAX_PIDS][MAX_CORES];

/* ── per-PID cache for the fast-path ring buffer push ───────────────────────
 * The slow path (200ms) computes SmoothedMetrics and stores them here.
 * The fast path (50ms) just copies these to g_rb with a fresh timestamp —
 * zero syscalls, classifier gets 50ms updates without 20 Hz perf reads.
 *
 * g_last_sm[i]       — aggregate entry (cpu_id = -1)
 * g_last_sm_pc[i][c] — per-core entry  (cpu_id = c); pid==0 means inactive
 *                       Only populated when g_cfg.per_core is true. */
static SmoothedMetrics g_last_sm   [MAX_PIDS];
static SmoothedMetrics g_last_sm_pc[MAX_PIDS][MAX_CORES];
static char            g_comm      [MAX_PIDS][17];

/* ── BUG 2 FIX: staleness tracking for the fast-path cache ─────────────────
 * g_last_sm_valid[i]     — true only after the slow path has computed at least
 *                          one real metric sample for slot i (d_cycles > 0).
 *                          Prevents the fast path from pushing a zero-init
 *                          SmoothedMetrics on the very first tick.
 * g_last_sm_timestamp[i] — CLOCK_MONOTONIC nanoseconds when the slow path last
 *                          wrote new metrics into g_last_sm[i].  The fast path
 *                          drops any entry older than STALE_THRESHOLD_NS so that
 *                          sleeping processes (d_cycles==0 every interval) do not
 *                          appear to the classifier as live CPU-bound work.
 *
 * BUG 3 FIX: both arrays must be kept in sync with g_last_sm during
 * remove_slot() swap operations — see the comment there. */
#define STALE_THRESHOLD_NS  500000000ULL  /* 500 ms — 2.5× the slow-path period */
static bool     g_last_sm_valid    [MAX_PIDS];
static uint64_t g_last_sm_timestamp[MAX_PIDS];

/* Per-core staleness timestamps ────────────────────────────────────────────
 * One timestamp per (slot, core) pair.  Stored as a flat array indexed by
 * PC_IDX(i, c) = i*MAX_CORES + c rather than a 2-D array to keep access
 * patterns cache-friendly: only the active-core stride is ever touched.
 *
 * When a process is idle on core C (dc_cyc==0) the slow path skips that
 * core without updating this timestamp.  The fast path checks the age before
 * pushing, so stale per-core entries age out at STALE_THRESHOLD_NS just like
 * the aggregate — the dashboard never shows a core column value that is more
 * than 500ms old. */
#define PC_IDX(i, c)  ((i) * MAX_CORES + (c))
static uint64_t g_last_sm_pc_timestamp[MAX_PIDS * MAX_CORES];

static int            g_ncores = 0;
static ebpf_tracer_t  g_tracer;
static RingBuffer    *g_rb       = NULL;   /* classifier buffer */
static RingBuffer    *g_rb_dash  = NULL;   /* dashboard buffer  */
static FILE          *g_csv      = NULL;
static int            g_n_active = 0;
static ProcScanner    g_scanner;

/* FIX 1: ring buffer drop counters ─────────────────────────────────────────
 * rb_push() is lossy — when the buffer is full it returns false and the
 * entry is silently dropped.  Without counters this is completely invisible:
 * the classifier sees a gap in timestamps but cannot distinguish idle process
 * from full buffer.  During benchmark evaluation, non-zero drops indicate:
 *   (a) Classifier is consuming too slowly — check consumer loop timing.
 *   (b) RB_CAPACITY in ring_buffer.h is too small for the active PID count.
 *   (c) A burst of sync_pids() added many PIDs at once.
 * Both counters are reported in cleanup() and appear in the systemd journal
 * at the end of every run, giving a clear pass/fail signal for data integrity.
 *
 * Separate counters for g_rb (classifier) and g_rb_dash (dashboard) because
 * they have independent consumers at different consumption rates. */
static uint64_t g_rb_drops      = 0;   /* classifier buffer (g_rb) */
static uint64_t g_rb_dash_drops = 0;   /* dashboard buffer  (g_rb_dash) */

/* Item 7: track process exits detected during the sampling loop.
 * When perf_counter_read() fails (ESRCH — process exited since last sync),
 * the slot is removed immediately rather than waiting for the next sync_pids()
 * call.  Counting these gives visibility into churn during benchmarks:
 * high counts during a steady-state workload indicate unexpected process
 * instability or very short-lived processes cycling through the top-N. */
static uint64_t g_proc_exits_mid_sample = 0;

/* Heartbeat counter — emits a one-line journal entry every 60 slow-path
 * ticks (~12 seconds at 200ms/tick).  Lets you confirm via 'journalctl -f'
 * that the daemon is alive during long benchmark runs. */
static int g_health_counter = 0;

static void handle_signal(int sig) { (void)sig; g_cfg.running = false; }

/* ── BUG 10 FIX: emergency crash handler ────────────────────────────────────
 * SIGTERM/SIGINT are handled above: they set g_cfg.running=false so the
 * sampling loop exits and cleanup() runs normally.
 *
 * SIGSEGV and SIGABRT are fatal — the process dies before cleanup() can run,
 * leaving /dev/shm/monitor_rb and /dev/shm/monitor_rb_dash on disk.
 * rb_create() does call shm_unlink() on the NEXT startup, so stale shm IS
 * cleaned automatically on restart — but if the restart is delayed, any
 * process that calls rb_attach() in the meantime maps a now-ownerless region
 * that will never be written again (stale data, or corrupted if the crash
 * happened mid-push).
 *
 * This handler provides defence-in-depth: it unlinks both shm objects so
 * consumers get a clean ENOENT rather than mapping stale memory, then
 * re-raises the signal with the default handler so the kernel can write a
 * core dump and systemd/journald record the correct crash exit status.
 *
 * ASYNC-SIGNAL-SAFETY: only async-signal-safe POSIX functions are used:
 *   shm_unlink() — POSIX.1-2008 async-signal-safe
 *   write()      — async-signal-safe (used instead of fprintf/printf)
 *   signal()     — async-signal-safe
 *   raise()      — async-signal-safe
 * No stdio, no malloc, no locks. */
static void handle_fatal_signal(int sig) {
    /* Best-effort shm removal — ignore return values; we cannot recover from
     * inside a signal handler, only clean up. */
    shm_unlink(SHM_NAME);
    shm_unlink(SHM_NAME_DASH);

    /* CSV data on crash:
     * fclose(g_csv) and fflush() are NOT async-signal-safe (they acquire
     * internal stdio locks) so they cannot be called here.  The kernel will
     * close the underlying fd on process exit, but any bytes in the stdio
     * buffer are lost.
     * Mitigation: setvbuf(g_csv, NULL, _IOLBF, 0) in main() makes the CSV
     * line-buffered, so at most ONE incomplete line can be in the buffer at
     * crash time.  All completed rows (terminated by '\n') were already
     * written via write() before the crash.  This is acceptable — a single
     * partial row at the end of the file is harmless for post-hoc analysis. */

    /* Emit a terse crash notice via write() (fprintf is NOT async-signal-safe) */
    static const char msg[] =
        "[daemon] FATAL signal received — shm unlinked, re-raising for core dump\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);

    /* Restore the default handler, then re-raise.  This causes the kernel to:
     *   1. Terminate with the correct signal (SIGSEGV/SIGABRT), not exit(1).
     *   2. Write a core dump if ulimit -c allows it.
     *   3. Report the correct exit status to systemd / the parent process. */
    signal(sig, SIG_DFL);
    raise(sig);
}

/* ── read_proc_comm ─────────────────────────────────────────────────────────
 * Read /proc/PID/comm — a single read() of at most 16 bytes.
 * Far cheaper than /proc/PID/stat which triggers do_task_stat, sscanf, etc.
 */
static void read_proc_comm(int pid, char *buf, int len) {
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { buf[0] = '\0'; return; }
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n > 0) {
        /* strip trailing newline */
        if (buf[n-1] == '\n') n--;
        buf[n] = '\0';
    } else {
        buf[0] = '\0';
    }
}

/* ── parse_args ─────────────────────────────────────────────────────────── */
static void parse_args(int argc, char **argv) {
    g_cfg.interval_ms   = DEFAULT_INTERVAL;
    g_cfg.terminal_mode = false;
    g_cfg.quiet_mode    = false;   /* --quiet: suppress all non-error output */
    g_cfg.n_pids        = 0;
    g_cfg.top_n         = 0;
    g_cfg.min_uid       = MIN_UID;
    g_cfg.csv_path      = NULL;
    g_cfg.per_core      = false;
    g_cfg.per_core_mask = 0;       /* 0 = all cores; set by --cores */

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pids") == 0 && i + 1 < argc) {
            i++;
            char *tok = strtok(argv[i], ",");
            while (tok && g_cfg.n_pids < MAX_PIDS) {
                g_cfg.pids[g_cfg.n_pids++] = atoi(tok);
                tok = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            g_cfg.top_n = atoi(argv[++i]);
            if (g_cfg.top_n <= 0 || g_cfg.top_n > MAX_PIDS)
                g_cfg.top_n = DEFAULT_TOP_N;
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            g_cfg.interval_ms = atoi(argv[++i]);
            if (g_cfg.interval_ms <= 0) g_cfg.interval_ms = DEFAULT_INTERVAL;
        } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            g_cfg.csv_path = argv[++i];
        } else if (strcmp(argv[i], "--min-uid") == 0 && i + 1 < argc) {
            g_cfg.min_uid = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--all") == 0) {
            /* Monitor ALL user processes — sets top_n to max */
            g_cfg.top_n = MAX_PIDS;
        } else if (strcmp(argv[i], "--per-core") == 0) {
            g_cfg.per_core = true;
        } else if (strcmp(argv[i], "--cores") == 0 && i + 1 < argc) {
            /* --cores 0,1,2,3 — monitor only these cores in per-core mode.
             * Implies --per-core.  Sets a bitmask so the sampling loop can
             * skip unmonitored cores, reducing per-core overhead from
             * g_ncores× down to N× for N specified cores.
             * Useful when a benchmark is pinned to specific cores via taskset
             * and you only want to see those cores in the dashboard. */
            i++;
            g_cfg.per_core = true;
            char *tok = strtok(argv[i], ",");
            while (tok) {
                int c = atoi(tok);
                if (c >= 0 && c < MAX_CORES)
                    g_cfg.per_core_mask |= (1ULL << c);
                tok = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "--quiet") == 0) {
            /* Suppress all non-error output — clean journal entries when
             * running as a systemd service.  Errors and WARNING lines are
             * always written to stderr regardless of this flag. */
            g_cfg.quiet_mode = true;
        } else if (strcmp(argv[i], "--terminal") == 0) {
            /* FIX: explicit opt-in to terminal output (use when running manually) */
            g_cfg.terminal_mode = true;
        } else if (strcmp(argv[i], "--daemon") == 0) {
            /* FIX: explicit daemon/service mode — suppress terminal output */
            g_cfg.terminal_mode = false;
        } else if (strcmp(argv[i], "--version") == 0) {
            /* FIX 7: print build provenance and exit cleanly.
             * Allows post-hoc identification of which binary produced a
             * given CSV or set of benchmark results. */
            printf("capstone_monitor  git=%s  built=%s\n", GIT_HASH, BUILD_DATE);
            exit(0);
        }
    }

    /* If neither --pids nor --top given, default to top 50 */
    if (g_cfg.n_pids == 0 && g_cfg.top_n == 0)
        g_cfg.top_n = DEFAULT_TOP_N;
}

/* ── slot management ────────────────────────────────────────────────────── */
static int find_slot(int pid) {
    for (int i = 0; i < g_n_active; i++)
        if (g_states[i].pid == pid) return i;
    return -1;
}

static int add_pid(int pid) {
    if (g_n_active >= MAX_PIDS) return -1;
    int i = g_n_active;

    /* 1. Clear stale data leftover from remove_slot shifting BEFORE opening */
    memset(&g_perf[i], 0, sizeof(g_perf[i]));
    if (g_cfg.per_core) {
        for (int c = 0; c < g_ncores; c++) {
            memset(&g_perf_pc[i][c], 0, sizeof(g_perf_pc[i][c]));
        }
    }

    /* ALWAYS open aggregate mode so the main sampling loop functions.
     * perf_counter_open falls back to PERF_TYPE_SOFTWARE if hardware PMU
     * is unavailable (VM, no CAP_PERFMON).  In that case hw_available=0
     * and IPC/LLC will be 0.0; ctx_freq and io_freq via eBPF still work. */
    if (perf_counter_open(&g_perf[i], (pid_t)pid, -1) != 0) {
        fprintf(stderr, "[daemon] perf_counter_open failed entirely for PID %d"
                        " (no hardware and no software fallback)\n", pid);
        /* BUG 4 FIX: do NOT call perf_counter_close here.
         * perf_counter_open already calls it internally before returning -1,
         * so all fds have been closed and reset to -1.  A second call would
         * be a no-op now (all fds are -1), but it is misleading and fragile.
         * The root fix — initialising fd_* to -1 after memset() at the top of
         * perf_counter_open() — is in perf_counter.c and ensures that any
         * partial-failure path never passes fd==0 to close(). */
        return -1;
    }

    if (g_cfg.per_core && g_perf[i].hw_available) {
        /* Per-core hardware counters — only meaningful when PMU is available */
        for (int c = 0; c < g_ncores; c++) {
            if (perf_counter_open(&g_perf_pc[i][c], (pid_t)pid, c) == 0) {
                sw_init(&g_win_ipc_pc[i][c]);
                sw_init(&g_win_llc_pc[i][c]);
            } else {
                perf_counter_close(&g_perf_pc[i][c]);
            }
        }
    }

    /* Clear and initialize the rest of the state variables.
     *
     * BUG 5 NOTE: ordering here is load-bearing for PID-reuse correctness.
     * When a PID slot is reused (old process exited, new process got same PID),
     * the memset below zeros ALL stale baselines (prev_cycles, prev_ctx, etc.)
     * before they are reseeded from the new process's current counters.
     * The sw_init calls that follow reset the sliding windows so the new
     * process's history does not inherit the old process's metric samples.
     * Do NOT reorder: memset must precede sw_init and counter seeding. */
    memset(&g_states[i], 0, sizeof(g_states[i]));
    memset(g_core_prev[i], 0, sizeof(g_core_prev[i]));
    memset(&g_last_sm[i], 0, sizeof(g_last_sm[i]));
    memset(g_last_sm_pc[i], 0, sizeof(g_last_sm_pc[i]));
    /* BUG 2 FIX: mark this slot's fast-path cache as invalid until the slow
     * path computes a real sample (d_cycles > 0).  Also reset the staleness
     * timestamp so that a reused slot from a previously-monitored PID does
     * not appear fresh to the fast path. */
    g_last_sm_valid    [i] = false;
    g_last_sm_timestamp[i] = 0;
    /* Per-core staleness timestamps — zero out for this slot so the fast
     * path never sees a non-zero age from a previously monitored PID. */
    for (int c = 0; c < MAX_CORES; c++)
        g_last_sm_pc_timestamp[PC_IDX(i, c)] = 0;
    /* g_states[i].prev_io is zeroed by the memset above */
    g_comm[i][0] = '\0';
    g_states[i].pid    = pid;
    g_states[i].active = 1;
    sw_init(&g_win_ipc[i]);
    sw_init(&g_win_llc[i]);
    sw_init(&g_win_ctx[i]);
    sw_init(&g_win_io[i]);

    /* Seed baselines so the first delta is ~0 not the process lifetime total */
    raw_counters_t seed;
    if (perf_counter_read(&g_perf[i], &seed) == 0) {
        g_states[i].prev_cycles       = seed.cycles;
        g_states[i].prev_instructions = seed.instructions;
        g_states[i].prev_llc          = seed.llc_misses;
    }
    g_states[i].prev_ctx = ebpf_tracer_read_switches(&g_tracer, (uint32_t)pid);
    g_states[i].prev_io  = ebpf_tracer_read_io(&g_tracer, (uint32_t)pid);

    /* Seed comm from the BPF exec_comms map (set at execve() time, no /proc
     * race).  Falls back to /proc/PID/comm if the exec tracepoint is
     * unavailable or the process exec'd before the tracepoint attached. */
    if (!ebpf_tracer_pop_exec_comm(&g_tracer, (uint32_t)pid,
                                   g_comm[i], sizeof(g_comm[i])))
        read_proc_comm(pid, g_comm[i], sizeof(g_comm[i]));

    g_n_active++;
    return i;
}

static void remove_slot(int i) {
    perf_counter_close(&g_perf[i]);
    if (g_cfg.per_core) {
        for (int c = 0; c < g_ncores; c++)
            perf_counter_close(&g_perf_pc[i][c]);
    }
    int last = g_n_active - 1;
    if (i != last) {
        g_states  [i] = g_states  [last];   /* includes prev_io */
        g_win_ipc [i] = g_win_ipc [last];
        g_win_llc [i] = g_win_llc [last];
        g_win_ctx [i] = g_win_ctx [last];
        g_win_io  [i] = g_win_io  [last];
        g_perf    [i] = g_perf    [last];
        g_last_sm [i] = g_last_sm [last];
        /* BUG 3 FIX: keep staleness-tracking arrays in sync with g_last_sm.
         * Without this, after a swap the valid/timestamp at position i still
         * describe the removed slot, not the moved slot.  The fast path would
         * then either push a stale entry (valid=true, old timestamp) or skip
         * a legitimately fresh entry (valid=false after recent computation). */
        g_last_sm_valid    [i] = g_last_sm_valid    [last];
        g_last_sm_timestamp[i] = g_last_sm_timestamp[last];
        g_last_sm_valid    [last] = false;
        g_last_sm_timestamp[last] = 0;
        memcpy(g_comm[i],          g_comm[last],          sizeof(g_comm[i]));
        memcpy(g_last_sm_pc[i],    g_last_sm_pc[last],    sizeof(g_last_sm_pc[i]));
        /* copy per-core arrays too */
        for (int c = 0; c < g_ncores; c++) {
            g_perf_pc   [i][c] = g_perf_pc   [last][c];
            g_win_ipc_pc[i][c] = g_win_ipc_pc[last][c];
            g_win_llc_pc[i][c] = g_win_llc_pc[last][c];
            g_core_prev [i][c] = g_core_prev [last][c];
            /* Per-core staleness: swap timestamps in sync with the data arrays
             * so the fast-path age check refers to the moved slot's last
             * sample time, not the evicted slot's. */
            uint64_t tmp_ts = g_last_sm_pc_timestamp[PC_IDX(i, c)];
            g_last_sm_pc_timestamp[PC_IDX(i, c)]    = g_last_sm_pc_timestamp[PC_IDX(last, c)];
            g_last_sm_pc_timestamp[PC_IDX(last, c)] = tmp_ts;
        }
    }
    g_n_active--;
}

/* ── sync_pids: reconcile monitored set with desired set ─────────────────
 *
 * Item 5 — two-tier PID discovery:
 *
 * FAST PATH (every 1 second):
 *   Build a PID list from two sources and call proc_scanner_scan_pids():
 *   (a) Currently tracked PIDs (g_states[].pid) — we already have them,
 *       no /proc walk needed to keep monitoring them.
 *   (b) eBPF active_pids map — PIDs that fork'd since the BPF program
 *       attached.  This catches newly spawned processes without a full walk.
 *   proc_scanner_scan_pids() opens only /proc/<pid>/stat for PIDs in the
 *   list, so cost is O(tracked + recently_forked) instead of O(all_procs).
 *   On a system with 500 processes and 50 tracked, this is ~10× cheaper.
 *
 * FULL SCAN (every 5 seconds):
 *   Call proc_scanner_scan() — the original full /proc walk.
 *   This is the ONLY reliable way to discover pre-existing long-running
 *   processes that existed before the BPF program attached and therefore
 *   never appear in active_pids.  Without this, those processes are never
 *   added to the monitored set at startup.
 *   5-second cadence: infrequent enough to not affect benchmark overhead
 *   but short enough that a new long-running process (e.g. a benchmark
 *   launched by a script) is discovered within one scan window.
 */
static void sync_pids(void) {
    static struct timespec last_sync;
    static struct timespec last_full_scan;
    static int first_run = 1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    int64_t elapsed_ns = (int64_t)(now.tv_sec - last_sync.tv_sec) * 1000000000LL
                       + (int64_t)(now.tv_nsec - last_sync.tv_nsec);

    /* 1-second throttle on any sync */
    if (!first_run && elapsed_ns < 1000000000LL)
        return;

    /* Decide whether this sync needs a full /proc walk */
    int64_t full_elapsed_ns = 0;
    if (!first_run)
        full_elapsed_ns = (int64_t)(now.tv_sec  - last_full_scan.tv_sec)  * 1000000000LL
                        + (int64_t)(now.tv_nsec - last_full_scan.tv_nsec);

    bool do_full_scan = first_run || (full_elapsed_ns >= 5000000000LL);

    first_run = 0;
    last_sync = now;

    if (do_full_scan) {
        /* Full /proc walk: discovers pre-existing long-running processes
         * the eBPF active_pids map would miss (they fork'd before attach). */
        last_full_scan = now;
        proc_scanner_scan(&g_scanner);
    } else {
        /* Fast path: combine currently-tracked PIDs with recently-forked
         * PIDs from the eBPF map, then call the targeted scanner.
         * No opendir("/proc") — only targeted /proc/<pid>/stat opens. */

        /* Step 1: collect currently tracked PIDs.
         * uint32_t matches proc_scanner_scan_pids() signature directly —
         * no cast needed, no strict-aliasing violation. */
        uint32_t pid_list[MAX_PIDS * 2];
        int n_pids = 0;
        for (int i = 0; i < g_n_active && n_pids < MAX_PIDS; i++)
            pid_list[n_pids++] = (uint32_t)g_states[i].pid;

        /* Step 2: add recently-forked PIDs from eBPF that aren't tracked yet.
         * Linear scan is fine — both sets are capped at MAX_PIDS (256). */
        uint32_t ebpf_pids[MAX_PIDS];
        int n_ebpf = ebpf_tracer_get_active_pids(&g_tracer, ebpf_pids, MAX_PIDS);
        for (int e = 0; e < n_ebpf && n_pids < MAX_PIDS * 2; e++) {
            uint32_t epid = ebpf_pids[e];
            bool already_tracked = false;
            for (int t = 0; t < g_n_active; t++) {
                if ((uint32_t)g_states[t].pid == epid) {
                    already_tracked = true;
                    break;
                }
            }
            if (!already_tracked)
                pid_list[n_pids++] = epid;
        }

        proc_scanner_scan_pids(&g_scanner, pid_list, n_pids);
    }

    if (g_cfg.n_pids > 0) {
        /* ── Explicit PID mode ─────────────────────────────────────────── */
        for (int i = 0; i < g_cfg.n_pids; i++) {
            if (find_slot(g_cfg.pids[i]) < 0)
                add_pid(g_cfg.pids[i]);
        }

        /* Evict dead static PIDs */
        for (int i = 0; i < g_n_active; ) {
            if (kill(g_states[i].pid, 0) == -1 && errno == ESRCH)
                remove_slot(i);
            else
                i++;
        }
    } else {
        /* ── Top-N mode ────────────────────────────────────────────────── */
        int top[MAX_PIDS];
        int fetch_n = (g_cfg.top_n > MAX_PIDS) ? MAX_PIDS : g_cfg.top_n;
        int n = proc_scanner_top_n(&g_scanner, top, fetch_n, g_cfg.min_uid);

        /* Mark all current slots inactive; reactivate those still in top-N */
        for (int i = 0; i < g_n_active; i++)
            g_states[i].active = 0;

        for (int i = 0; i < n; i++) {
            int slot = find_slot(top[i]);
            if (slot < 0)
                slot = add_pid(top[i]);
            if (slot >= 0)
                g_states[slot].active = 1;
        }

        /* Evict processes that dropped out of top-N to free perf FDs */
        for (int i = 0; i < g_n_active; ) {
            if (g_states[i].active == 0)
                remove_slot(i);
            else
                i++;
        }
    }
}

/* ── Item 4: inline sd_notify — no libsystemd dependency ───────────────────
 * Sends "READY=1" to the systemd notification socket so that the service
 * manager transitions from "activating" to "active" and any services declared
 * After=capstone_monitor.service can start.
 *
 * Implemented inline rather than via libsystemd to keep the dependency list
 * minimal.  This is exactly what sd_notify(3) does internally:
 *   1. Read NOTIFY_SOCKET from the environment.
 *   2. Send a datagram to that socket path.
 *   3. Close the socket immediately.
 *
 * When not running under systemd (e.g. manual invocation) NOTIFY_SOCKET is
 * unset and the function returns silently — no error, no crash.
 *
 * Requires Type=notify in the [Service] section of the unit file. */
static void sd_notify_ready(void) {
    const char *sock_path = getenv("NOTIFY_SOCKET");
    if (!sock_path || sock_path[0] == '\0')
        return;   /* not running under systemd — nothing to do */

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("[daemon] sd_notify: socket");
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    /* NOTIFY_SOCKET can be an abstract socket (starts with '@') or a
     * filesystem path.  Abstract sockets use a NUL byte as the first char
     * of sun_path. */
    if (sock_path[0] == '@') {
        addr.sun_path[0] = '\0';
        strncpy(addr.sun_path + 1, sock_path + 1, sizeof(addr.sun_path) - 2);
    } else {
        strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    }

    static const char msg[] = "READY=1";
    if (sendto(fd, msg, sizeof(msg) - 1, MSG_NOSIGNAL,
               (struct sockaddr *)&addr, sizeof(addr)) < 0)
        perror("[daemon] sd_notify: sendto");

    close(fd);
}

/* ── init ───────────────────────────────────────────────────────────────── */
static void init_ebpf(const char *bpf_path) {
    if (ebpf_tracer_load(&g_tracer, bpf_path) != 0) {
        fprintf(stderr, "[daemon] FATAL: cannot load eBPF from '%s'\n", bpf_path);
        fprintf(stderr, "  Hint: use an absolute path, e.g. /opt/capstone_monitor/bpf/ctx_switch.bpf.o\n");
        exit(1);
    }
    if (ebpf_tracer_attach(&g_tracer) != 0) {
        fprintf(stderr, "[daemon] FATAL: cannot attach eBPF\n");
        ebpf_tracer_destroy(&g_tracer); exit(1);
    }
}

static void init_shm(void) {
    g_rb = rb_create();
    if (!g_rb) {
        fprintf(stderr, "[daemon] FATAL: cannot create shm\n"); exit(1);
    }
    g_rb_dash = rb_create_dash();
    if (!g_rb_dash) {
        fprintf(stderr, "[daemon] FATAL: cannot create dash shm\n"); exit(1);
    }
    LOG_INFO("[daemon] Ring buffers ready: " SHM_NAME " and " SHM_NAME_DASH "\n");
}

/* ── sampling loop ──────────────────────────────────────────────────────── */
static void run_sampling_loop(void) {
    int sample_num = 0;

    /* Time the slow path to get accurate ctx_freq denominators */
    struct timespec last_slow;
    clock_gettime(CLOCK_MONOTONIC, &last_slow);

    /* Print header once (terminal mode only) */
    if (g_cfg.terminal_mode)
        printf("%-6s  %-4s  %-16s  %-8s  %-10s  %-10s  %-10s\n",
               "PID", "CORE", "COMM", "IPC", "LLC_miss%", "ctx/sec", "io/sec");

    while (g_cfg.running) {
        struct timespec t_start;
        clock_gettime(CLOCK_MONOTONIC, &t_start);
        uint64_t now_ns = (uint64_t)t_start.tv_sec * 1000000000ULL
                        + (uint64_t)t_start.tv_nsec;

        /* ══════════════════════════════════════════════════════════════
         * SLOW PATH — runs every 4th tick (200ms)
         * All syscalls live here: perf reads, BPF lookups, proc scan.
         * 4× fewer kernel crossings vs running everything every 50ms.
         * ══════════════════════════════════════════════════════════════ */
        if (sample_num % 4 == 0) {
            /* Actual wall time since last slow-path call for accurate rates */
            /* Compute elapsed since last slow path in seconds.
             * Must use signed 64-bit ns arithmetic before dividing —
             * if tv_nsec(now) < tv_nsec(last), the naive double subtraction
             * (tv_nsec_now - tv_nsec_last) * 1e-9 underflows for unsigned
             * and produces a large positive error of ~1 second. */
            int64_t slow_dt_ns = (int64_t)(t_start.tv_sec  - last_slow.tv_sec)
                                           * 1000000000LL
                               + (int64_t)(t_start.tv_nsec - last_slow.tv_nsec);
            double slow_dt = (slow_dt_ns > 0) ? (double)slow_dt_ns * 1e-9
                                               : 0.200; /* guard first call */
            last_slow = t_start;

            sync_pids();

            /* Heartbeat: emit a compact status line every 60 slow-path ticks
             * (~12 seconds).  Appears in the systemd journal so you can confirm
             * the daemon is alive during long benchmark runs with:
             *   journalctl -u capstone_monitor -f
             * Respects --quiet (LOG_INFO is suppressed when quiet_mode=true). */
            if (++g_health_counter >= 60) {
                g_health_counter = 0;
                LOG_INFO("[daemon] heartbeat: %d PIDs active"
                         "  drops=cl:%" PRIu64 " dash:%" PRIu64
                         "  exits=%" PRIu64 "\n",
                         g_n_active,
                         g_rb_drops, g_rb_dash_drops,
                         g_proc_exits_mid_sample);
            }

            int display_limit = g_cfg.top_n > 0 ? g_cfg.top_n : g_n_active;
            int displayed = 0;

            for (int i = 0; i < g_n_active && displayed < display_limit; i++) {
                int pid = g_states[i].pid;

                raw_counters_t cur_hw;
                if (perf_counter_read(&g_perf[i], &cur_hw) != 0) {
                    /* Process exited between sync_pids() and now.
                     *
                     * Item 7 — i-- pattern explanation (load-bearing):
                     * remove_slot(i) swaps slot i with slot g_n_active-1 and
                     * decrements g_n_active.  After the swap, the slot that
                     * was at position last is now at position i — it has not
                     * been examined yet.  The for-loop's i++ would skip it.
                     * The i-- counteracts the i++ so the next iteration
                     * re-examines index i, which now holds the moved slot.
                     * Without i--, one in every two processes after a removal
                     * would be silently skipped for this slow-path tick. */
                    g_proc_exits_mid_sample++;
                    remove_slot(i--);
                    continue;
                }

                /* BPF ctx-switch read (one bpf() syscall per PID per 200ms) */
                uint64_t cur_ctx =
                    ebpf_tracer_read_switches(&g_tracer, (uint32_t)pid);

                /* BPF block I/O read — returns 0 if tracepoint unavailable */
                uint64_t cur_io =
                    ebpf_tracer_read_io(&g_tracer, (uint32_t)pid);

                uint64_t d_cycles = cur_hw.cycles       - g_states[i].prev_cycles;
                uint64_t d_instr  = cur_hw.instructions - g_states[i].prev_instructions;
                uint64_t d_llc    = cur_hw.llc_misses   - g_states[i].prev_llc;
                uint64_t d_ctx    = cur_ctx              - g_states[i].prev_ctx;
                uint64_t d_io     = cur_io               - g_states[i].prev_io;

                /* Always advance the hw and bpf-ctx baselines unconditionally.
                 * But do NOT advance prev_io when d_cycles==0: an I/O-bound
                 * process doing disk I/O while its CPU is idle (d_cycles==0)
                 * would otherwise have its I/O events silently consumed and
                 * dropped from the window — exactly the worst case for
                 * I/O-bound classification.  By leaving prev_io unchanged,
                 * the accumulated d_io carries forward to the next interval. */
                g_states[i].prev_cycles       = cur_hw.cycles;
                g_states[i].prev_instructions = cur_hw.instructions;
                g_states[i].prev_llc          = cur_hw.llc_misses;
                g_states[i].prev_ctx          = cur_ctx;

                /* Skip idle processes for metric computation — IPC=0 and
                 * LLC_miss=0 are meaningless for a process not running.
                 * prev_io is NOT advanced here so IO events accumulate. */
                if (d_cycles == 0) { displayed++; continue; }

                /* Now safe to advance prev_io — process was actually running */
                g_states[i].prev_io = cur_io;

                double ipc      = (double)d_instr / (double)d_cycles;
                double llc_rate = d_instr > 0
                                  ? (double)d_llc / (double)d_instr : 0.0;
                double ctx_freq = (double)d_ctx / slow_dt;
                double io_freq  = (double)d_io  / slow_dt;

                sw_push(&g_win_ipc[i], ipc);
                sw_push(&g_win_llc[i], llc_rate);
                sw_push(&g_win_ctx[i], ctx_freq);
                sw_push(&g_win_io[i],  io_freq);

                /* Update per-PID cache for the fast path */
                g_last_sm[i].pid               = pid;
                g_last_sm[i].cpu_id            = -1;
                g_last_sm[i].smoothed_ipc      = sw_mean(&g_win_ipc[i]);
                g_last_sm[i].smoothed_llc_miss = sw_mean(&g_win_llc[i]);
                g_last_sm[i].smoothed_ctx_freq = sw_mean(&g_win_ctx[i]);
                g_last_sm[i].smoothed_io_freq  = sw_mean(&g_win_io[i]);
                /* BUG 2 FIX: record when this entry was last computed from a
                 * real sample (d_cycles > 0) and mark it valid.  The fast
                 * path will skip this entry once it ages beyond
                 * STALE_THRESHOLD_NS, preventing a sleeping process from
                 * appearing as live CPU-bound work to the classifier. */
                g_last_sm_valid    [i] = true;
                g_last_sm_timestamp[i] = now_ns;
                /* timestamp written in fast path each tick */

                /* Dashboard buffer (aggregate, ~200ms cadence) */
                if (g_rb_dash != NULL) {
                    g_last_sm[i].timestamp_ns = now_ns;
                    if (!rb_push(g_rb_dash, &g_last_sm[i]))
                        g_rb_dash_drops++;
                }

                /* Per-core (only with --per-core; data only needed by dashboard) */
                if (g_cfg.per_core) {
                    for (int c = 0; c < g_ncores; c++) {
                        /* --cores mask: skip cores not selected (0 = all) */
                        if (g_cfg.per_core_mask != 0
                            && !(g_cfg.per_core_mask & (1ULL << c)))
                            continue;
                        raw_counters_t cc;
                        if (perf_counter_read(&g_perf_pc[i][c], &cc) != 0) {
                            /* FIX 3: reset baselines on read failure.
                             * If we just 'continue', prev_* keeps the last
                             * good snapshot.  The NEXT successful read will
                             * compute a delta spanning multiple intervals,
                             * producing a false IPC/LLC spike in the smoothed
                             * window.  Zeroing prev_* means the first delta
                             * after a failed read is computed against zero,
                             * which yields an overcount for one interval but
                             * recovers correctly on the interval after that —
                             * far less harmful than a multi-interval spike. */
                            g_core_prev[i][c].prev_cycles = 0;
                            g_core_prev[i][c].prev_instr  = 0;
                            g_core_prev[i][c].prev_llc    = 0;
                            continue;
                        }

                        uint64_t dc_cyc = cc.cycles       - g_core_prev[i][c].prev_cycles;
                        uint64_t dc_ins = cc.instructions - g_core_prev[i][c].prev_instr;
                        uint64_t dc_llc = cc.llc_misses   - g_core_prev[i][c].prev_llc;

                        g_core_prev[i][c].prev_cycles = cc.cycles;
                        g_core_prev[i][c].prev_instr  = cc.instructions;
                        g_core_prev[i][c].prev_llc    = cc.llc_misses;

                        if (dc_cyc == 0) continue;
                        /* Per-core idle staleness is now handled correctly:
                         * when dc_cyc==0 we skip updating g_last_sm_pc_timestamp,
                         * so the fast-path staleness check ages out this core's
                         * entry at STALE_THRESHOLD_NS.  The dashboard will show
                         * no data for an idle core rather than a stale value. */

                        double pc_ipc = (double)dc_ins / (double)dc_cyc;
                        double pc_llc = dc_ins > 0
                                        ? (double)dc_llc / (double)dc_ins : 0.0;

                        sw_push(&g_win_ipc_pc[i][c], pc_ipc);
                        sw_push(&g_win_llc_pc[i][c], pc_llc);

                        /* Populate per-core cache for the fast path.
                         * ctx_freq and io_freq are process-wide (BPF maps
                         * are per-PID, not per-core), copied from aggregate. */
                        g_last_sm_pc[i][c].pid               = pid;
                        g_last_sm_pc[i][c].cpu_id            = c;
                        g_last_sm_pc[i][c].smoothed_ipc      = sw_mean(&g_win_ipc_pc[i][c]);
                        g_last_sm_pc[i][c].smoothed_llc_miss = sw_mean(&g_win_llc_pc[i][c]);
                        g_last_sm_pc[i][c].smoothed_ctx_freq = g_last_sm[i].smoothed_ctx_freq;
                        g_last_sm_pc[i][c].smoothed_io_freq  = g_last_sm[i].smoothed_io_freq;
                        g_last_sm_pc[i][c].timestamp_ns      = now_ns;
                        /* Per-core staleness: record last sample time for this
                         * core independently of other cores and the aggregate.
                         * The fast path checks PC_IDX(i,c) age before pushing. */
                        g_last_sm_pc_timestamp[PC_IDX(i, c)] = now_ns;

                        /* Push to both buffers at slow-path cadence.
                         * Fast path re-pushes with fresh timestamps every 50ms. */
                        if (g_rb      != NULL && !rb_push(g_rb,      &g_last_sm_pc[i][c])) g_rb_drops++;
                        if (g_rb_dash != NULL && !rb_push(g_rb_dash, &g_last_sm_pc[i][c])) g_rb_dash_drops++;

                        if (g_cfg.terminal_mode)
                            printf("%-6d  %-4d  %-16s  %-8.3f  %-10.4f  %-10.1f  %-10.1f\n",
                                   pid, c, "-",
                                   g_last_sm_pc[i][c].smoothed_ipc,
                                   g_last_sm_pc[i][c].smoothed_llc_miss,
                                   g_last_sm_pc[i][c].smoothed_ctx_freq,
                                   g_last_sm_pc[i][c].smoothed_io_freq);
                    }
                }

                if (g_csv)
                    fprintf(g_csv, "%d,%" PRIu64 ",%.4f,%.6f,%.2f,%.2f\n",
                            pid, now_ns,
                            g_last_sm[i].smoothed_ipc,
                            g_last_sm[i].smoothed_llc_miss,
                            g_last_sm[i].smoothed_ctx_freq,
                            g_last_sm[i].smoothed_io_freq);

                /* Update comm: prefer BPF exec_comms (no /proc race, zero cost
                 * when process hasn't exec'd).  Falls back to /proc/PID/comm
                 * for long-running processes that exec'd before tracepoint
                 * attached, or when the exec tracepoint is unavailable. */
                if (!ebpf_tracer_pop_exec_comm(&g_tracer, (uint32_t)pid,
                                               g_comm[i], sizeof(g_comm[i])))
                    read_proc_comm(pid, g_comm[i], sizeof(g_comm[i]));

                if (g_cfg.terminal_mode)
                    printf("%-6d  %-4s  %-16s  %-8.3f  %-10.4f  %-10.1f  %-10.1f\n",
                           pid, "agg", g_comm[i],
                           g_last_sm[i].smoothed_ipc,
                           g_last_sm[i].smoothed_llc_miss,
                           g_last_sm[i].smoothed_ctx_freq,
                           g_last_sm[i].smoothed_io_freq);

                displayed++;
            }

            if (g_cfg.terminal_mode) {
                LOG_DEBUG("----\n");
                if (g_cfg.terminal_mode) fflush(stdout);
            }
        } /* end slow path */

        /* ══════════════════════════════════════════════════════════════
         * FAST PATH — every tick (50ms)
         * Push cached SmoothedMetrics to the classifier ring buffer.
         * ZERO syscalls: just struct copies into shared memory.
         * Classifier sees fresh timestamps every 50ms as required.
         *
         * Per-core push volume: MAX_PIDS × (1 + ncores) entries/tick.
         * RB_CAPACITY in ring_buffer.h must be >= MAX_PIDS*(1+MAX_CORES).
         * ══════════════════════════════════════════════════════════════ */
        for (int i = 0; i < g_n_active; i++) {
            /* Aggregate (cpu_id = -1) */
            /* BUG 2 FIX: two guards before pushing to the classifier buffer.
             *
             * 1. g_last_sm_valid[i] — false until the slow path has computed
             *    at least one real sample (d_cycles > 0).  Prevents pushing
             *    a zero-init SmoothedMetrics on the very first tick(s) before
             *    the slow path has run.
             *
             * 2. Staleness check — if the slow path last updated this entry
             *    more than STALE_THRESHOLD_NS ago, the process has been idle
             *    (d_cycles==0 every slow-path interval since then) and its
             *    cached IPC/LLC values no longer reflect its current behaviour.
             *    Skipping it stops the classifier from seeing a sleeping process
             *    as "CPU-bound" indefinitely with a fresh timestamp. */
            if (!g_last_sm_valid[i]) continue;
            if (now_ns - g_last_sm_timestamp[i] > STALE_THRESHOLD_NS) continue;
            g_last_sm[i].timestamp_ns = now_ns;
            if (!rb_push(g_rb, &g_last_sm[i]))
                g_rb_drops++;

            /* Per-core (cpu_id = 0..ncores-1) — only in per-core mode */
            if (g_cfg.per_core) {
                for (int c = 0; c < g_ncores; c++) {
                    /* --cores mask: skip unselected cores (0 = all) */
                    if (g_cfg.per_core_mask != 0
                        && !(g_cfg.per_core_mask & (1ULL << c)))
                        continue;
                    if (g_last_sm_pc[i][c].pid == 0) continue;
                    /* Per-core staleness: use independent per-core timestamp
                     * so a core that hasn't run in >500ms is suppressed even
                     * if the aggregate is still fresh (process runs on other
                     * cores).  This fixes the previously-documented limitation
                     * where idle-core cached IPC kept being pushed forever. */
                    if (now_ns - g_last_sm_pc_timestamp[PC_IDX(i, c)]
                            > STALE_THRESHOLD_NS) continue;
                    g_last_sm_pc[i][c].timestamp_ns = now_ns;
                    if (!rb_push(g_rb, &g_last_sm_pc[i][c]))
                        g_rb_drops++;
                }
            }
        }

        /* Sleep to next 50ms boundary using absolute deadline.
         *
         * OLD: relative sleep = interval - elapsed.  Two problems:
         *   1. tv_nsec subtraction underflows when t_now.tv_nsec < t_start.tv_nsec
         *      producing a negative elapsed_ns cast to large positive long.
         *   2. Each tick accumulates drift: the next tick starts from when
         *      we wake rather than from the intended deadline.
         *
         * FIX: TIMER_ABSTIME sleeps until an absolute CLOCK_MONOTONIC
         *      deadline = t_start + interval.  The kernel handles the
         *      nsec carry correctly and drift cannot accumulate.
         *
         * BUG 6 FIX: use int64_t for ALL intermediate nsec arithmetic.
         * With 'long interval_ns' and 'tv_nsec + interval_ns % 1e9', the
         * sum can reach ~1,999,999,998 — which overflows a 32-bit long
         * (max 2,147,483,647) for intervals above ~1147ms on 32-bit targets.
         * Although x86-64 has 64-bit long, using int64_t makes the
         * arithmetic portable and self-documenting.  The carry is now
         * computed by integer division rather than a conditional branch,
         * which is also cleaner. */
        int64_t interval_ns  = (int64_t)g_cfg.interval_ms * 1000000LL;
        int64_t deadline_ns  = (int64_t)t_start.tv_nsec
                             + (interval_ns % 1000000000LL);
        struct timespec deadline = {
            /* Integer division handles the carry: if deadline_ns >= 1e9,
             * the extra second is folded into tv_sec automatically. */
            .tv_sec  = t_start.tv_sec
                       + (time_t)(interval_ns  / 1000000000LL)
                       + (time_t)(deadline_ns  / 1000000000LL),
            .tv_nsec = (long)     (deadline_ns  % 1000000000LL),
        };
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        sample_num++;
    }
}


static void cleanup(void) {
    for (int i = 0; i < g_n_active; i++) {
        perf_counter_close(&g_perf[i]);
        if (g_cfg.per_core)
            for (int c = 0; c < g_ncores; c++)
                perf_counter_close(&g_perf_pc[i][c]);
    }
    ebpf_tracer_destroy(&g_tracer);
    /* FIX 1: report ring buffer drops before destroying the buffers.
     * Zero drops = all data reached the classifier / dashboard.
     * Non-zero drops = either RB_CAPACITY needs increasing or the consumer
     * is too slow.  Both counters appear in the systemd journal on shutdown,
     * giving a clear data-integrity signal after every benchmark run. */
    if (g_rb_drops > 0)
        LOG_ERROR("[daemon] WARNING: classifier ring buffer drops: %"
                PRIu64 " entries lost\n", g_rb_drops);
    else
        LOG_INFO("[daemon] classifier ring buffer: 0 drops (OK)\n");
    if (g_rb_dash_drops > 0)
        LOG_ERROR("[daemon] WARNING: dashboard ring buffer drops: %"
                PRIu64 " entries lost\n", g_rb_dash_drops);
    LOG_INFO("[daemon] process exits detected mid-sample: %"
            PRIu64 "\n", g_proc_exits_mid_sample);
    if (g_rb)      rb_destroy(g_rb);
    if (g_rb_dash) rb_destroy_dash(g_rb_dash);
    if (g_csv) fclose(g_csv);
    LOG_INFO("[daemon] Clean shutdown.\n");
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <bpf.o> [OPTIONS]\n\n"
            "Options:\n"
            "  --top N        Monitor top N processes by CPU usage (default: %d)\n"
            "  --pids P1,P2   Monitor specific PIDs explicitly\n"
            "  --all          Monitor all user processes\n"
            "  --interval MS  Sample interval in ms (default: %d)\n"
            "  --csv FILE     Write samples to CSV\n"
            "  --min-uid UID  Minimum UID for top-N scan (default: %d)\n"
            "  --per-core     Enable per-core hardware counter tracking\n"
            "  --cores N,M    Monitor only cores N,M,... (implies --per-core)\n"
            "  --terminal     Enable terminal/stdout output (manual use)\n"
            "  --daemon       Suppress terminal output (for service use, default)\n"
            "  --quiet        Suppress all non-error output (clean journal)\n"
            "  --version      Print build date and git hash, then exit\n\n"
            "Examples:\n"
            "  sudo %s /opt/capstone_monitor/bpf/ctx_switch.bpf.o --top 5 --terminal\n"
            "  sudo %s /opt/capstone_monitor/bpf/ctx_switch.bpf.o --top 10 --csv out.csv --terminal\n"
            "  sudo %s /opt/capstone_monitor/bpf/ctx_switch.bpf.o --pids 1234,5678 --terminal\n"
            "  sudo %s /opt/capstone_monitor/bpf/ctx_switch.bpf.o --all --min-uid 0 --terminal\n",
            argv[0],
            DEFAULT_TOP_N, DEFAULT_INTERVAL, MIN_UID,
            argv[0], argv[0], argv[0], argv[0]);
        exit(1);
    }

    const char *bpf_path = argv[1];
    parse_args(argc - 2, argv + 2);
    g_cfg.running = true;

    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);
    /* BUG 10 FIX: catch fatal signals so shm regions are unlinked before the
     * process dies.  See handle_fatal_signal() above for rationale. */
    signal(SIGSEGV, handle_fatal_signal);
    signal(SIGABRT, handle_fatal_signal);
    /* Fix 3: ignore SIGPIPE.
     * The default SIGPIPE handler terminates the process, which bypasses
     * cleanup() and leaves shm objects in /dev/shm.  Sources of SIGPIPE:
     *   - fprintf(g_csv, ...) when the CSV is on an NFS mount that drops.
     *   - fprintf(g_csv, ...) when the underlying fd is closed externally.
     *   - Any write() to a pipe-backed stdout (e.g. | head in a shell).
     * With SIG_IGN, stdio write calls return -1 with errno=EPIPE and the
     * sampling loop continues.  The CSV row is lost but the daemon survives.
     * The next write attempt will also fail, so the CSV effectively stops
     * producing output — visible in the journal as missed rows — without
     * crashing the monitoring session. */
    signal(SIGPIPE, SIG_IGN);

    g_ncores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (g_ncores <= 0 || g_ncores > MAX_CORES) g_ncores = 2;
    if (g_cfg.per_core) {
        LOG_INFO("[daemon] Per-core mode enabled: %d cores\n", g_ncores);
    }
    proc_scanner_init(&g_scanner);
    init_ebpf(bpf_path);
    init_shm();
    /* Item 4: notify systemd that initialisation is complete and the daemon
     * is ready to serve.  Requires Type=notify in the unit file.
     * No-op when NOTIFY_SOCKET is unset (manual invocation). */
    sd_notify_ready();

    if (g_cfg.csv_path) {
        g_csv = fopen(g_cfg.csv_path, "w");
        if (!g_csv) { perror("fopen csv"); exit(1); }
        setvbuf(g_csv, NULL, _IOLBF, 0);
        fprintf(g_csv, "pid,timestamp_ns,ipc,llc_miss,ctx_freq,io_freq\n");
    }

    /* Suppress noisy startup messages in daemon/service mode — they go to
     * the journal and add clutter without value.  In --terminal mode they
     * are useful for interactive debugging. */
    if (g_cfg.n_pids > 0) {
        LOG_INFO("[daemon] Explicit PID mode: %d PIDs\n", g_cfg.n_pids);
    } else {
        LOG_INFO("[daemon] Top-%d mode (uid >= %d), interval=%dms\n",
               g_cfg.top_n, g_cfg.min_uid, g_cfg.interval_ms);
    }

    run_sampling_loop();
    cleanup();
    return 0;
}
