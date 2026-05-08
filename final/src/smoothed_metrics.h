#ifndef SMOOTHED_METRICS_H
#define SMOOTHED_METRICS_H

#include <stdint.h>

/*
 * SmoothedMetrics — one entry in the ring buffer.
 *
 * Memory layout (sizeof == 48):
 *   offset  0  int      pid
 *   offset  4  int      cpu_id       -1 = aggregate, 0..N = specific core
 *   offset  8  uint64_t timestamp_ns
 *   offset 16  double   smoothed_ipc
 *   offset 24  double   smoothed_llc_miss  (fraction, NOT percent)
 *   offset 32  double   smoothed_ctx_freq  (voluntary switches/sec)
 *   offset 40  double   smoothed_io_freq   (block I/O completions/sec)
 *
 * smoothed_io_freq is 0.0 when the block tracepoint is unavailable or
 * the process issued no block I/O in the current window.
 * The classifier uses it as the primary I/O-bound signal — it is a
 * cleaner signal than ctx_freq, which conflates I/O waits with mutex
 * and sleep-based voluntary context switches.
 *
 * All consumers (classifier, dashboard, ghOSt agent) must be compiled
 * against this header.  The struct layout changed from 40 to 48 bytes.
 */
typedef struct {
    int      pid;
    int      cpu_id;            /* -1 = aggregate mode, >=0 = per-core mode */
    uint64_t timestamp_ns;      /* CLOCK_MONOTONIC */
    double   smoothed_ipc;
    double   smoothed_llc_miss;
    double   smoothed_ctx_freq;
    double   smoothed_io_freq;  /* block I/O completions/sec; 0 if unavailable */
} SmoothedMetrics;

#endif /* SMOOTHED_METRICS_H */
