#!/bin/bash
# =============================================================================
# validate_overhead.sh — measure capstone_monitor daemon CPU overhead
#
# Methodology:
#   1. Stop the daemon and measure baseline CPU idle% for DURATION seconds.
#   2. Start the daemon and measure CPU idle% again for DURATION seconds.
#   3. Overhead = baseline_idle% - daemon_idle%  (positive = daemon used that %).
#   4. Also check the journal for ring buffer drops after the run.
#
# Requirements:
#   - sysstat package (mpstat):  sudo apt install sysstat
#   - systemd service installed: sudo make install
#
# Usage:
#   sudo ./scripts/validate_overhead.sh [DURATION_SECONDS]
#
# Example:
#   sudo ./scripts/validate_overhead.sh 60
#
# Output (example):
#   === Baseline idle: 97.42 % ===
#   === Daemon idle:   94.89 % ===
#   === Overhead:       2.53 % ===   <-- should be < 5%
#   === Ring buffer drops: 0 ===
# =============================================================================

set -euo pipefail

DURATION=${1:-60}   # seconds per measurement window; default 60
SERVICE=capstone_monitor

# ── sanity checks ─────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must be run as root (needs systemctl and perf access)" >&2
    exit 1
fi

if ! command -v mpstat &>/dev/null; then
    echo "ERROR: mpstat not found — install sysstat:  sudo apt install sysstat" >&2
    exit 1
fi

if ! systemctl list-unit-files "${SERVICE}.service" &>/dev/null; then
    echo "ERROR: ${SERVICE}.service not installed." \
         "Run 'sudo make install' first." >&2
    exit 1
fi

# ── helper: measure average CPU idle% over $1 seconds ─────────────────────
measure_idle() {
    local dur=$1
    # mpstat 1 N prints N 1-second samples then an Average line.
    # The idle column is the last field on the Average line.
    mpstat 1 "$dur" 2>/dev/null \
        | awk '/^Average:/ { print $NF; exit }'
}

# ── baseline: daemon stopped ───────────────────────────────────────────────
echo "Stopping ${SERVICE} for baseline measurement..."
systemctl stop "${SERVICE}" 2>/dev/null || true
sleep 2   # let the system settle after daemon exit

echo "Measuring baseline CPU idle% (${DURATION}s)..."
BASELINE_IDLE=$(measure_idle "$DURATION")
echo "=== Baseline idle: ${BASELINE_IDLE} % ==="

# ── daemon running ─────────────────────────────────────────────────────────
echo ""
echo "Starting ${SERVICE}..."
systemctl start "${SERVICE}"
sleep 5   # allow daemon to discover processes and warm up the sliding windows

echo "Measuring daemon CPU idle% (${DURATION}s)..."
DAEMON_IDLE=$(measure_idle "$DURATION")
echo "=== Daemon idle:   ${DAEMON_IDLE} % ==="

# ── compute overhead ───────────────────────────────────────────────────────
OVERHEAD=$(awk -v b="$BASELINE_IDLE" -v d="$DAEMON_IDLE" \
               'BEGIN { printf "%.2f", b - d }')
echo "=== Overhead:       ${OVERHEAD} % ==="

if awk -v o="$OVERHEAD" 'BEGIN { exit (o <= 5.0) ? 0 : 1 }'; then
    echo "    PASS — overhead <= 5% target"
else
    echo "    FAIL — overhead > 5% target (investigate with: top -d0.5 -p \$(pgrep monitor_final))"
fi

# ── ring buffer drops ──────────────────────────────────────────────────────
echo ""
echo "=== Ring buffer drops (last 2 minutes) ==="
DROP_LINES=$(journalctl -u "${SERVICE}" --since "2 min ago" \
             --no-pager 2>/dev/null \
             | grep -E "drops|WARNING|heartbeat" || true)

if [[ -z "$DROP_LINES" ]]; then
    echo "    No drop or heartbeat lines found (daemon may not have run long enough)"
else
    echo "$DROP_LINES"
fi

# ── summary ───────────────────────────────────────────────────────────────
echo ""
echo "=== Summary ==="
echo "  Baseline idle : ${BASELINE_IDLE} %"
echo "  Daemon idle   : ${DAEMON_IDLE} %"
echo "  Overhead      : ${OVERHEAD} %  (target: < 5%)"
echo ""
echo "  For your report: record baseline and daemon idle% from a"
echo "  CPU-bound / memory-bound / I/O-bound sysbench run with the"
echo "  daemon enabled and disabled, then report the delta."
