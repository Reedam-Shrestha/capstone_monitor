#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdatomic.h>
#include <stdbool.h>
#include "smoothed_metrics.h"

/* RB_CAPACITY must be a power of 2 and large enough to hold one full
 * fast-path push burst without dropping.
 *
 * Worst case: MAX_PIDS=256, MAX_CORES=64
 *   per-core push per tick = 256 * (1 + 64) = 16640 entries
 *
 * 4096 (old value) is catastrophically too small — it would drop ~75% of
 * entries every tick in full per-core mode.  32768 gives 2x headroom.
 *
 * The static_assert below will catch any future reduction of this value. */
#define RB_CAPACITY    32768

/* These values must match MAX_PIDS and MAX_CORES in monitor_final.h.
 * Defined here independently to avoid ring_buffer.h pulling in the
 * application-level monitor_final.h header (which would create an
 * upward dependency from transport layer to application layer). */
#define RB_MAX_PIDS    256
#define RB_MAX_CORES    64
_Static_assert(RB_CAPACITY >= RB_MAX_PIDS * (1 + RB_MAX_CORES),
    "RB_CAPACITY too small for per-core mode: must be >= MAX_PIDS*(1+MAX_CORES)");
_Static_assert((RB_CAPACITY & (RB_CAPACITY - 1)) == 0,
    "RB_CAPACITY must be a power of 2");

#define SHM_NAME       "/monitor_rb"       /* classifier buffer */
#define SHM_NAME_DASH  "/monitor_rb_dash"  /* dashboard buffer  */

typedef struct {
    SmoothedMetrics slots[RB_CAPACITY];
    atomic_int      head;      /* producer writes here */
    atomic_int      tail;      /* consumer reads from here */
    /* NOTE: capacity field removed — all paths use the RB_CAPACITY
     * compile-time constant directly.  Having a runtime field that could
     * diverge from the constant was the source of the rb_pop/rb_is_full
     * modulo asymmetry bug (different values after stale shm reattach). */
} RingBuffer;

/* ── Producer side ───────────────────────────────────────────────────────── */
RingBuffer *rb_create      (void);           /* creates /monitor_rb      */
RingBuffer *rb_create_dash (void);           /* creates /monitor_rb_dash */
bool        rb_push        (RingBuffer *rb, const SmoothedMetrics *m);

/* ── Consumer side ───────────────────────────────────────────────────────── */
RingBuffer *rb_attach      (void);           /* attaches /monitor_rb      */
RingBuffer *rb_attach_dash (void);           /* attaches /monitor_rb_dash */
bool        rb_pop         (RingBuffer *rb, SmoothedMetrics *out);

/* ── Shared cleanup ──────────────────────────────────────────────────────── */
void rb_destroy     (RingBuffer *rb);        /* unmap + unlink /monitor_rb      */
void rb_destroy_dash(RingBuffer *rb);        /* unmap + unlink /monitor_rb_dash */
void rb_detach      (RingBuffer *rb);        /* unmap only — no unlink          */

bool rb_is_full (const RingBuffer *rb);
bool rb_is_empty(const RingBuffer *rb);

#endif /* RING_BUFFER_H */
