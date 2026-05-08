#ifndef EBPF_TRACER_H
#define EBPF_TRACER_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

typedef struct {
    struct bpf_object *obj;
    struct bpf_link   *link_sched_switch;  /* sched_switch attachment */
    struct bpf_link   *link_fork;          /* sched_process_fork attachment */
    struct bpf_link   *link_exit;          /* sched_process_exit attachment */
    struct bpf_link   *link_block;         /* block_rq_complete attachment (may be NULL) */
    struct bpf_link   *link_exec;          /* sched_process_exec attachment */
    int                map_fd_switches;    /* vol_ctx_switches map fd */
    int                map_fd_pids;        /* active_pids map fd */
    int                map_fd_io;          /* io_counts map fd (-1 if unavailable) */
    int                map_fd_exec;        /* exec_comms map fd (-1 if unavailable) */
    int                loaded;
} ebpf_tracer_t;

/* Load the BPF object file into the kernel */
int      ebpf_tracer_load(ebpf_tracer_t *et, const char *bpf_path);

/* Attach all tracepoints (block_rq_complete is non-fatal if unavailable) */
int      ebpf_tracer_attach(ebpf_tracer_t *et);

/* Read cumulative voluntary switches for one PID */
uint64_t ebpf_tracer_read_switches(const ebpf_tracer_t *et, uint32_t pid);

/* Read cumulative block I/O completions for one PID.
 * Returns 0 if the io_counts map is unavailable. */
uint64_t ebpf_tracer_read_io(const ebpf_tracer_t *et, uint32_t pid);

/* Read and consume the exec comm for a PID from the exec_comms map.
 * Copies up to len-1 bytes into buf and null-terminates it.
 * Deletes the map entry after reading so it doesn't accumulate.
 * Returns 1 if a comm was found, 0 if not (map unavailable or no entry). */
int ebpf_tracer_pop_exec_comm(const ebpf_tracer_t *et,
                               uint32_t pid, char *buf, int len);

/* Get the current list of active user PIDs discovered by fork/exit hooks.
 * Fills pids[] with up to max_pids entries.
 * Returns the number of PIDs written. */
int      ebpf_tracer_get_active_pids(const ebpf_tracer_t *et,
                                     uint32_t *pids, int max_pids);

/* Detach all tracepoints and free resources */
void     ebpf_tracer_destroy(ebpf_tracer_t *et);

#endif /* EBPF_TRACER_H */
