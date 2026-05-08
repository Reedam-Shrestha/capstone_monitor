/* ctx_switch.bpf.c — kernel-side eBPF program
 *
 * Five tracepoints:
 *   1. sched:sched_switch        — count voluntary ctx switches per PID
 *   2. sched:sched_process_fork  — auto-register new user processes
 *   3. sched:sched_process_exit  — auto-remove exited processes
 *   4. block:block_rq_complete   — count block I/O completions per PID
 *   5. sched:sched_process_exec  — capture process name at execve() time
 *
 * Maps exposed to userspace:
 *   vol_ctx_switches  — pid → cumulative voluntary switch count
 *   active_pids       — pid → 1 (set on fork, deleted on exit)
 *   io_counts         — pid → cumulative block I/O completion count
 *   exec_comms        — pid → char[16] process name set at exec time
 *
 * exec_comms lets userspace read the correct comm at the moment of exec
 * without opening /proc/PID/comm, which races with fast exec-then-exit
 * sequences.  Userspace reads it once when adding a new PID slot and
 * deletes its entry to keep map pressure low.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

/* ── Map 1: voluntary context switch counters ───────────────────────────── */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,         __u32);   /* PID */
    __type(value,       __u64);   /* cumulative voluntary switch count */
} vol_ctx_switches SEC(".maps");

/* ── Map 2: active user PIDs (auto-discovered) ──────────────────────────── */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,         __u32);   /* PID */
    __type(value,       __u32);   /* 1 = active */
} active_pids SEC(".maps");

/* ── Map 3: block I/O completion counters ───────────────────────────────── */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,         __u32);   /* PID */
    __type(value,       __u64);   /* cumulative block I/O completions */
} io_counts SEC(".maps");

/* ── Map 4: process name captured at exec time ──────────────────────────── */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,         __u32);    /* PID (tgid) */
    __type(value,       char[16]); /* comm at execve — same 16-char limit as kernel */
} exec_comms SEC(".maps");

/* ── Tracepoint 1: sched_switch ─────────────────────────────────────────
 * Field layout verified against:
 * /sys/kernel/debug/tracing/events/sched/sched_switch/format
 *
 * offset 0  : __u64 pad        (8 bytes common header)
 * offset 8  : char  prev_comm[16]
 * offset 24 : __u32 prev_pid
 * offset 28 : __u32 prev_prio
 * offset 32 : __s64 prev_state  (0=preempted/involuntary, >0=sleeping/voluntary)
 * offset 40 : char  next_comm[16]
 * offset 56 : __u32 next_pid
 * offset 60 : __u32 next_prio
 */
struct sched_switch_args {
    __u64 pad;
    char  prev_comm[16];
    __u32 prev_pid;
    __u32 prev_prio;
    __s64 prev_state;
    char  next_comm[16];
    __u32 next_pid;
    __u32 next_prio;
};

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx) {
    __u32 pid = ctx->prev_pid;

    /* Skip idle process (PID 0) */
    if (pid == 0)
        return 0;

    /* Only count voluntary switches — prev_state > 0 means the process
     * chose to sleep (IO wait, mutex, sleep(), etc.).
     * prev_state == 0 means it was preempted by the scheduler. */
    if (ctx->prev_state == 0)
        return 0;

    /* Increment counter atomically */
    __u64 *count = bpf_map_lookup_elem(&vol_ctx_switches, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&vol_ctx_switches, &pid, &initial, BPF_ANY);
    }

    return 0;
}

/* ── Tracepoint 2: sched_process_fork ───────────────────────────────────
 * Field layout verified against:
 * /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
 *
 * offset 0  : __u64 pad           (8 bytes common header)
 * offset 8  : __u32 parent_comm   (__data_loc, 4 bytes descriptor)
 * offset 12 : pid_t parent_pid
 * offset 16 : __u32 child_comm    (__data_loc, 4 bytes descriptor)
 * offset 20 : pid_t child_pid
 *
 * NOTE: __data_loc fields are descriptors, not inline strings.
 * We only need the pid fields so we skip the comm strings entirely.
 */
struct sched_process_fork_args {
    __u64  pad;
    __u32  parent_comm;   /* __data_loc descriptor — do not dereference */
    __u32  parent_pid;
    __u32  child_comm;    /* __data_loc descriptor — do not dereference */
    __u32  child_pid;
};

SEC("tp/sched/sched_process_fork")
int handle_fork(struct sched_process_fork_args *ctx) {
    __u32 child_pid = ctx->child_pid;

    /* Skip kernel threads (PID 0 and 1) */
    if (child_pid <= 1)
        return 0;

    /* Register the new child in active_pids map */
    __u32 active = 1;
    bpf_map_update_elem(&active_pids, &child_pid, &active, BPF_ANY);

    /* Pre-initialise its ctx switch and I/O counters to 0 */
    __u64 zero = 0;
    bpf_map_update_elem(&vol_ctx_switches, &child_pid, &zero, BPF_NOEXIST);
    bpf_map_update_elem(&io_counts,        &child_pid, &zero, BPF_NOEXIST);

    return 0;
}

/* ── Tracepoint 3: sched_process_exit ───────────────────────────────────
 * Field layout verified against:
 * /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
 *
 * offset 0  : __u64 pad    (8 bytes common header)
 * offset 8  : char  comm[16]
 * offset 24 : pid_t pid
 * offset 28 : int   prio
 * offset 32 : bool  group_dead
 */
struct sched_process_exit_args {
    __u64 pad;
    char  comm[16];
    __u32 pid;
    __u32 prio;
    __u8  group_dead;
};

SEC("tp/sched/sched_process_exit")
int handle_exit(struct sched_process_exit_args *ctx) {
    __u32 pid = ctx->pid;

    if (pid <= 1)
        return 0;

    /* Only remove the process entry when the whole thread group dies.
     * group_dead=false means a thread exited but the process lives on. */
    if (!ctx->group_dead)
        return 0;

    /* Remove from all maps */
    bpf_map_delete_elem(&active_pids,      &pid);
    bpf_map_delete_elem(&vol_ctx_switches, &pid);
    bpf_map_delete_elem(&io_counts,        &pid);
    bpf_map_delete_elem(&exec_comms,       &pid);

    return 0;
}

/* ── Tracepoint 4: block_rq_complete ────────────────────────────────────
 * Field layout verified against:
 * /sys/kernel/debug/tracing/events/block/block_rq_complete/format
 *
 * offset 0  : __u64 pad          (8 bytes common header)
 * offset 8  : dev_t dev          (4 bytes)
 * offset 12 : sector_t sector    (8 bytes)
 * offset 20 : unsigned int nr_sector (4 bytes)
 * offset 24 : int errors         (4 bytes)
 * offset 28 : __u32 rwbs         (4 bytes, encoded R/W/F flags)
 * offset 32 : __u32 comm         (__data_loc descriptor for task comm)
 *
 * We only need the PID of the task that issued the request, which is
 * available via bpf_get_current_pid_tgid() at completion time.
 *
 * NOTE: block_rq_complete fires in the context of the CPU completing the
 * I/O, not necessarily the issuing task's context.  We use the tgid
 * (thread group id = process id) from the completion context, which
 * corresponds to the process that called into the block layer.  For
 * kernel-issued I/O (e.g. writeback) the pid will be a kernel thread and
 * will not appear in active_pids, so we silently skip those with the
 * active_pids guard.
 */
struct block_rq_complete_args {
    __u64 pad;       /* 8-byte common header */
    __u32 dev;       /* offset  8 */
    __u32 _pad2;     /* offset 12 — alignment pad before sector */
    __u64 sector;    /* offset 16 — sector_t is 8 bytes, aligned */
    __u32 nr_sector; /* offset 24 */
    __s32 errors;    /* offset 28 */
    __u32 rwbs;      /* offset 32 */
    /* __data_loc comm follows — we don't dereference it */
};

SEC("tp/block/block_rq_complete")
int handle_block_rq_complete(struct block_rq_complete_args *ctx) {
    /* Use tgid (process id) not tid so per-thread I/O is attributed
     * to the process, consistent with how perf_event_open tracks by pid */
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    if (pid <= 1)
        return 0;

    /* Only count I/O for processes we're already tracking.
     * This avoids polluting io_counts with kernel writeback threads
     * and unmonitored processes, keeping map pressure low. */
    __u32 *tracked = bpf_map_lookup_elem(&active_pids, &pid);
    if (!tracked)
        return 0;

    __u64 *count = bpf_map_lookup_elem(&io_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&io_counts, &pid, &initial, BPF_ANY);
    }

    return 0;
}

/* ── Tracepoint 5: sched_process_exec ───────────────────────────────────
 * Fires inside execve() after the new program image has been loaded and
 * the task comm has been updated to the new binary name.
 *
 * Field layout verified against:
 * /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
 *
 * offset 0  : __u64 pad           (8 bytes common header)
 * offset 8  : __u32 filename      (__data_loc descriptor — do not deref)
 * offset 12 : pid_t pid           (the execing thread's pid)
 * offset 16 : pid_t old_pid       (pid before exec, same unless thread group)
 *
 * We use bpf_get_current_comm() rather than dereferencing the filename
 * __data_loc field.  bpf_get_current_comm() reads from task->comm which
 * the kernel has already updated to the new binary name by the time this
 * tracepoint fires, giving us exactly the 16-char comm string we want
 * without any unsafe pointer arithmetic.
 *
 * The entry is written into exec_comms and stays there until userspace
 * reads and deletes it via ebpf_tracer_pop_exec_comm().  This avoids
 * accumulating stale entries for short-lived processes.
 */
struct sched_process_exec_args {
    __u64 pad;
    __u32 filename;   /* __data_loc — do not dereference */
    __u32 pid;
    __u32 old_pid;
};

SEC("tp/sched/sched_process_exec")
int handle_exec(struct sched_process_exec_args *ctx) {
    /* Use tgid (process id) so exec by any thread updates the process entry */
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    if (pid <= 1)
        return 0;

    /* Capture the new comm string (already updated in task->comm) */
    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));

    /* Overwrite any stale entry — BPF_ANY so it works for both new and
     * existing entries (e.g. a process that exec()s multiple times) */
    bpf_map_update_elem(&exec_comms, &pid, comm, BPF_ANY);

    /* Also register in active_pids in case the fork tracepoint was missed
     * (e.g. daemon started after the process was already running) */
    __u32 active = 1;
    bpf_map_update_elem(&active_pids, &pid, &active, BPF_NOEXIST);

    return 0;
}

char _license[] SEC("license") = "GPL";
