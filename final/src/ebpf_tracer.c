#include "ebpf_tracer.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ── helpers ────────────────────────────────────────────────────────────── */

static int find_map_fd(struct bpf_object *obj, const char *name) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    if (!map) {
        fprintf(stderr, "[ebpf_tracer] Cannot find map '%s'\n", name);
        return -1;
    }
    int fd = bpf_map__fd(map);
    if (fd < 0)
        fprintf(stderr, "[ebpf_tracer] bpf_map__fd('%s') failed\n", name);
    return fd;
}

static struct bpf_link *attach_prog(struct bpf_object *obj,
                                    const char *prog_name) {
    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "[ebpf_tracer] Cannot find program '%s'\n", prog_name);
        return NULL;
    }
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link)
        fprintf(stderr, "[ebpf_tracer] attach '%s' failed: %s\n",
                prog_name, strerror(errno));
    return link;
}

/* ── ebpf_tracer_load ───────────────────────────────────────────────────── */

int ebpf_tracer_load(ebpf_tracer_t *et, const char *bpf_path) {
    memset(et, 0, sizeof(*et));
    et->map_fd_switches = -1;
    et->map_fd_pids     = -1;
    et->map_fd_io       = -1;
    et->map_fd_exec     = -1;

    et->obj = bpf_object__open(bpf_path);
    if (!et->obj) {
        fprintf(stderr, "[ebpf_tracer] bpf_object__open(%s) failed: %s\n",
                bpf_path, strerror(errno));
        return -1;
    }

    int err = bpf_object__load(et->obj);
    if (err) {
        fprintf(stderr, "[ebpf_tracer] bpf_object__load failed: %s\n",
                strerror(-err));
        fprintf(stderr, "  Hint: /sys/kernel/btf/vmlinux must exist\n");
        fprintf(stderr, "  Hint: run as root\n");
        bpf_object__close(et->obj);
        et->obj = NULL;
        return -1;
    }

    et->map_fd_switches = find_map_fd(et->obj, "vol_ctx_switches");
    et->map_fd_pids     = find_map_fd(et->obj, "active_pids");
    /* io_counts map — non-fatal if missing (kernel may not expose
     * block tracepoints in all configurations) */
    et->map_fd_io   = find_map_fd(et->obj, "io_counts");
    if (et->map_fd_io < 0)
        fprintf(stderr, "[ebpf_tracer] io_counts map unavailable"
                        " — I/O freq will be 0\n");

    /* exec_comms map — non-fatal; falls back to /proc/PID/comm */
    et->map_fd_exec = find_map_fd(et->obj, "exec_comms");
    if (et->map_fd_exec < 0)
        fprintf(stderr, "[ebpf_tracer] exec_comms map unavailable"
                        " — comm will be read from /proc\n");

    if (et->map_fd_switches < 0 || et->map_fd_pids < 0) {
        bpf_object__close(et->obj);
        et->obj = NULL;
        return -1;
    }

    et->loaded = 1;
    printf("[ebpf_tracer] Loaded %s  switches_fd=%d  pids_fd=%d  io_fd=%d\n",
           bpf_path, et->map_fd_switches, et->map_fd_pids, et->map_fd_io);
    return 0;
}

/* ── ebpf_tracer_attach ─────────────────────────────────────────────────── */

int ebpf_tracer_attach(ebpf_tracer_t *et) {
    if (!et->loaded) {
        fprintf(stderr, "[ebpf_tracer] Not loaded.\n");
        return -1;
    }

    et->link_sched_switch = attach_prog(et->obj, "handle_sched_switch");
    et->link_fork         = attach_prog(et->obj, "handle_fork");
    et->link_exit         = attach_prog(et->obj, "handle_exit");

    if (!et->link_sched_switch || !et->link_fork || !et->link_exit) {
        fprintf(stderr, "[ebpf_tracer] One or more attach calls failed.\n");
        return -1;
    }

    /* Block I/O tracepoint — non-fatal if unavailable (some kernel configs
     * disable block tracepoints; also requires CONFIG_BLK_DEV_IO_TRACE) */
    et->link_block = attach_prog(et->obj, "handle_block_rq_complete");
    if (!et->link_block)
        fprintf(stderr, "[ebpf_tracer] block_rq_complete attach failed"
                        " — I/O freq will be 0 (non-fatal)\n");

    /* exec tracepoint — non-fatal; falls back to /proc/PID/comm polling */
    et->link_exec = attach_prog(et->obj, "handle_exec");
    if (!et->link_exec)
        fprintf(stderr, "[ebpf_tracer] sched_process_exec attach failed"
                        " — comm read from /proc (non-fatal)\n");

    printf("[ebpf_tracer] Attached: sched_switch + fork + exit%s%s\n",
           et->link_block ? " + block_rq_complete" : "",
           et->link_exec  ? " + sched_process_exec" : "");
    return 0;
}

/* ── ebpf_tracer_read_switches ──────────────────────────────────────────── */

uint64_t ebpf_tracer_read_switches(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_switches < 0) return 0;
    uint64_t count = 0;
    bpf_map_lookup_elem(et->map_fd_switches, &pid, &count);
    return count;
}

/* ── ebpf_tracer_read_io ────────────────────────────────────────────────
 * Returns cumulative block I/O completions for pid, or 0 if the
 * io_counts map is unavailable (block tracepoint not attached).
 */
uint64_t ebpf_tracer_read_io(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_io < 0) return 0;
    uint64_t count = 0;
    bpf_map_lookup_elem(et->map_fd_io, &pid, &count);
    return count;
}

/* ── ebpf_tracer_get_active_pids ────────────────────────────────────────
 * Iterates the active_pids BPF hash map and returns all current keys.
 * Uses bpf_map_get_next_key to walk the map without knowing keys upfront.
 */
int ebpf_tracer_get_active_pids(const ebpf_tracer_t *et, uint32_t *pids, int max_pids) {
    if (et->map_fd_pids < 0) return 0;

    uint32_t batch_keys[8192];
    uint32_t batch_values[8192];
    uint32_t batch_count = max_pids > 8192 ? 8192 : max_pids;
    
    /* HARDWIRED FIX: 1 single system call instead of a while loop of 300+ syscalls */
    int err = bpf_map_lookup_batch(et->map_fd_pids, NULL, NULL, 
                                   batch_keys, batch_values, &batch_count, NULL);
    
    if (err == 0 || (err < 0 && errno == ENOENT)) {
        for (uint32_t i = 0; i < batch_count; i++) {
            pids[i] = batch_keys[i];
        }
        return batch_count;
    }
    return 0;
}

/* ── ebpf_tracer_destroy ────────────────────────────────────────────────── */

void ebpf_tracer_destroy(ebpf_tracer_t *et) {
    if (et->link_sched_switch) {
        bpf_link__destroy(et->link_sched_switch);
        et->link_sched_switch = NULL;
    }
    if (et->link_fork) {
        bpf_link__destroy(et->link_fork);
        et->link_fork = NULL;
    }
    if (et->link_exit) {
        bpf_link__destroy(et->link_exit);
        et->link_exit = NULL;
    }
    if (et->link_block) {
        bpf_link__destroy(et->link_block);
        et->link_block = NULL;
    }
    if (et->link_exec) {
        bpf_link__destroy(et->link_exec);
        et->link_exec = NULL;
    }
    if (et->obj) {
        bpf_object__close(et->obj);
        et->obj = NULL;
    }
    et->map_fd_switches = -1;
    et->map_fd_pids     = -1;
    et->map_fd_io       = -1;
    et->map_fd_exec     = -1;
    et->loaded = 0;
    printf("[ebpf_tracer] Destroyed.\n");
}

/* ── ebpf_tracer_pop_exec_comm ──────────────────────────────────────────────
 * Reads and deletes the exec comm for pid from the exec_comms BPF map.
 * Call this once when adding a new PID slot — it gives you the correct
 * binary name set at execve() time without any /proc race.
 * Falls back gracefully when map is unavailable (returns 0).
 */
int ebpf_tracer_pop_exec_comm(const ebpf_tracer_t *et,
                               uint32_t pid, char *buf, int len) {
    if (et->map_fd_exec < 0 || !buf || len <= 0)
        return 0;

    char comm[16] = {};
    if (bpf_map_lookup_elem(et->map_fd_exec, &pid, comm) != 0)
        return 0;   /* no entry — process exec'd before our tracepoint attached */

    /* Copy safely and null-terminate */
    int copy_len = len - 1 < 16 ? len - 1 : 16;
    int i;
    for (i = 0; i < copy_len && comm[i] != '\0'; i++)
        buf[i] = comm[i];
    buf[i] = '\0';

    /* Delete the entry — we've consumed it, keep map pressure low */
    bpf_map_delete_elem(et->map_fd_exec, &pid);
    return 1;
}
