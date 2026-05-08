#ifndef PERF_COUNTER_H
#define PERF_COUNTER_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    uint64_t cycles;
    uint64_t instructions;
    uint64_t llc_misses;
} raw_counters_t;

typedef struct {
    pid_t    pid;
    int      cpu_id;        /* -1 = aggregate (follow process), >=0 = pinned core */
    int      fd_cycles;
    int      fd_instr;
    int      fd_llc;
    int      hw_available;  /* 1 = hardware PMU open, 0 = software fallback */
    uint64_t id_cycles;
    uint64_t id_instr;
    uint64_t id_llc;
    /* NOTE: per-interval delta tracking (prev_cycles etc.) lives in
     * PidState / CorePrev in monitor_final.h — not here.  The fields
     * that used to be here were never written by perf_counter.c and
     * caused confusion about where the canonical baseline lives. */
} perf_counter_t;

/*
 * Open grouped hardware counters for a process.
 *   cpu_id = -1  : follow the process across all cores (aggregate)
 *   cpu_id >= 0  : pin to that specific core
 */
int    perf_counter_open (perf_counter_t *pc, pid_t pid, int cpu_id);
int    perf_counter_read (perf_counter_t *pc, raw_counters_t *out);
void   perf_counter_close(perf_counter_t *pc);

double perf_counter_ipc          (const raw_counters_t *cur,
                                  const raw_counters_t *prev);
double perf_counter_llc_miss_rate(const raw_counters_t *cur,
                                  const raw_counters_t *prev);

#endif /* PERF_COUNTER_H */
