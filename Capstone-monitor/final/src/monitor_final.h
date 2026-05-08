#ifndef MONITOR_FINAL_H
#define MONITOR_FINAL_H

#include <stdint.h>
#include <stdbool.h>
#include "sliding_window.h"

#define MAX_PIDS         256
#define MAX_CORES         64    /* max CPU cores supported in per-core mode */
#define DEFAULT_INTERVAL  50
#define DEFAULT_TOP_N     50   /* default top-N when --top is used */
#define MIN_UID         1000   /* only monitor user processes by default */
/* NOTE: SWAG_N removed — use SWAG_CAPACITY from sliding_window.h directly.
 * Having two defines for the same constant (both = 10) caused confusion
 * about which one was authoritative. */

typedef struct {
    int      pid;
    int      active;
    uint64_t prev_cycles;
    uint64_t prev_instructions;
    uint64_t prev_llc;
    uint64_t prev_ctx;
    uint64_t prev_io;   /* baseline for block I/O completion delta */
} PidState;

typedef struct {
    int   pids[MAX_PIDS];  /* explicit PIDs if --pids used */
    int   n_pids;          /* 0 = use top_n mode */
    int   top_n;           /* N for top-N mode (0 = disabled) */
    int   min_uid;         /* minimum UID to include in top-N scan */
    int   interval_ms;
    char *csv_path;
    bool  terminal_mode;
    bool  running;
    bool  per_core;
    bool  quiet_mode;        /* --quiet: suppress all non-error output         */
    uint64_t per_core_mask;  /* --cores bitmask: bit C=1 → monitor core C;
                              * 0 means monitor all cores                       */
} DaemonConfig;

#endif /* MONITOR_FINAL_H */
