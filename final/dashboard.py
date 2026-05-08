"""
Real-Time Performance Monitor Dashboard
Reads from shared-memory ring buffer written by monitor_final.
Usage: python3 dashboard.py [--top 20] [--sort cpu|mem|ipc] [--interval 2]
"""

import os, sys, time, mmap, struct, ctypes, argparse
from dataclasses import dataclass, field
from typing import Dict

from rich.console import Console
from rich.table   import Table
from rich.live    import Live
from rich.panel   import Panel
from rich         import box

# ── ring buffer constants — must match ring_buffer.h ─────────────────────────
SHM_PATH = "/dev/shm/monitor_rb_dash"   # dashboard-only buffer
SLOT     = 40    # sizeof(SmoothedMetrics) with padding
CAP      = 4096  # RB_CAPACITY in ring_buffer.h

# ── C struct layout:
#   int      pid          offset 0  size 4
#   int      _pad         offset 4  size 4   (compiler alignment)
#   uint64   timestamp_ns offset 8  size 8
#   double   ipc          offset 16 size 8
#   double   llc_miss     offset 24 size 8
#   double   ctx_freq     offset 32 size 8
#   total = 40 bytes
# RingBuffer layout: slots[CAP] first, then atomic_int head, atomic_int tail, int capacity
# So head is at offset SLOT*CAP, tail at SLOT*CAP+4

class SmoothedMetrics(ctypes.Structure):
    _fields_ = [
        ("pid",               ctypes.c_int),
        ("cpu_id",            ctypes.c_int),      # -1=aggregate, >=0=core id
        ("timestamp_ns",      ctypes.c_uint64),
        ("smoothed_ipc",      ctypes.c_double),
        ("smoothed_llc_miss", ctypes.c_double),
        ("smoothed_ctx_freq", ctypes.c_double),
    ]


# ── threshold loader — reads calibrate.py output ─────────────────────────────
_CONF_PATH = os.path.expanduser("~/.config/capstone_monitor/thresholds.conf")
_DEFAULTS  = {
    "ipc_cpu_threshold": 1.2,
    "ipc_mem_threshold": 0.8,
    "llc_mem_threshold": 0.02,
    "ctx_io_threshold":  500.0,
}

def load_thresholds() -> dict:
    t = dict(_DEFAULTS)
    if not os.path.exists(_CONF_PATH):
        return t
    try:
        for line in open(_CONF_PATH):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if key in t:
                t[key] = float(val.strip())
    except Exception:
        pass
    return t

_thresholds  = load_thresholds()
_thresh_mtime = 0.0


# ── workload classifier ───────────────────────────────────────────────────────
def classify(ipc: float, llc_miss: float, ctx_freq: float):
    """
    Rule-based classifier using calibrated thresholds.
    Re-reads thresholds.conf if it has changed on disk (live recalibration).
    Labelled 'Est.Workload' in UI to distinguish from Bigyan's authoritative
    classifier which feeds the scheduler.
    """
    global _thresholds, _thresh_mtime
    try:
        mt = os.path.getmtime(_CONF_PATH)
        if mt != _thresh_mtime:
            _thresholds   = load_thresholds()
            _thresh_mtime = mt
    except Exception:
        pass

    t = _thresholds
    if ipc > t["ipc_cpu_threshold"] and ctx_freq < t["ctx_io_threshold"]:
        return "CPU-BOUND", "green"
    if llc_miss > t["llc_mem_threshold"] and ipc < t["ipc_mem_threshold"]:
        return "MEM-BOUND", "yellow"
    if ctx_freq > t["ctx_io_threshold"]:
        return "IO-BOUND",  "red"
    if ipc < 0.05:
        return "IDLE",      "dim"
    return "MIXED",         "blue"


# ── ring buffer drain ─────────────────────────────────────────────────────────
def drain_ring_buffer() -> Dict[int, SmoothedMetrics]:
    """
    Pop all pending entries from the ring buffer.
    Returns most recent SmoothedMetrics per PID.
    Moving tail forward so the daemon never sees 'ring buffer full'.
    """
    result: Dict[int, SmoothedMetrics] = {}
    if not os.path.exists(SHM_PATH):
        return result

    slots_sz = SLOT * CAP
    try:
        actual  = os.path.getsize(SHM_PATH)
        fd      = os.open(SHM_PATH, os.O_RDWR)
        mm      = mmap.mmap(fd, actual, access=mmap.ACCESS_WRITE)
        os.close(fd)
    except Exception:
        return result

    try:
        # head = producer index (written by daemon, read-only here)
        # tail = consumer index (we advance this as we pop)
        head_off = slots_sz
        tail_off = slots_sz + 4
        head = int.from_bytes(mm[head_off:head_off+4], 'little')
        tail = int.from_bytes(mm[tail_off:tail_off+4], 'little')

        drained = 0
        while tail != head and drained < CAP:
            idx    = tail % CAP
            offset = idx * SLOT
            chunk  = bytes(mm[offset:offset+SLOT])

            pid = int.from_bytes(chunk[0:4],  'little', signed=True)
            ts  = int.from_bytes(chunk[8:16], 'little')

            if 0 < pid < 4194304 and ts > 0:
                ipc = struct.unpack_from('d', chunk, 16)[0]
                if 0.0 <= ipc <= 20.0:   # sanity: discard garbage slots
                    m = SmoothedMetrics.from_buffer_copy(chunk)
                    if pid not in result or ts > result[pid].timestamp_ns:
                        result[pid] = m

            # advance tail — this is the consumer pop
            new_tail = (tail + 1) % CAP
            mm[tail_off:tail_off+4] = new_tail.to_bytes(4, 'little')
            tail    = new_tail
            drained += 1

    except Exception:
        pass
    finally:
        mm.close()

    return result


# ── /proc helpers ─────────────────────────────────────────────────────────────
def read_proc_stat(pid: int):
    try:
        with open(f"/proc/{pid}/stat") as f:
            line = f.read()
        comm_s = line.index('(') + 1
        comm_e = line.rindex(')')
        comm   = line[comm_s:comm_e]
        rest   = line[comm_e+2:].split()
        return comm, int(rest[11]) + int(rest[12])
    except Exception:
        return None

def read_proc_status(pid: int):
    rss_kb, threads = 0, 0
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_kb  = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
    except Exception:
        pass
    return rss_kb, threads


# ── per-PID display state ─────────────────────────────────────────────────────
@dataclass
class PidInfo:
    pid:        int   = 0
    comm:       str   = ""
    cpu_pct:    float = 0.0
    rss_mb:     float = 0.0
    threads:    int   = 0
    ipc:        float = 0.0
    llc_miss:   float = 0.0
    ctx_freq:   float = 0.0
    prev_ticks: int   = 0
    seen:       bool  = False
    last_seen:  float = field(default_factory=time.time)


# ── dashboard ─────────────────────────────────────────────────────────────────
class Dashboard:
    def __init__(self, top_n: int, interval: float, sort_by: str = "cpu"):
        self.top_n    = top_n
        self.interval = interval
        self.sort_by  = sort_by
        self.state:  Dict[int, PidInfo] = {}
        self.hz      = os.sysconf("SC_CLK_TCK")
        self.ncores  = os.cpu_count() or 1

    def update(self):
        rb_data = drain_ring_buffer()
        now     = time.time()

        for info in self.state.values():
            info.seen = False

        for pid, m in rb_data.items():
            stat = read_proc_stat(pid)
            if not stat:
                continue
            comm, total_ticks = stat
            rss_kb, threads   = read_proc_status(pid)

            if pid not in self.state:
                self.state[pid] = PidInfo(pid=pid, prev_ticks=total_ticks)

            info             = self.state[pid]
            info.comm        = comm
            info.rss_mb      = rss_kb / 1024
            info.threads     = threads
            info.seen        = True
            info.last_seen   = now

            delta            = total_ticks - info.prev_ticks
            info.cpu_pct     = (delta / (self.interval * self.hz)) * 100 / self.ncores
            info.prev_ticks  = total_ticks

            info.cpu_id      = m.cpu_id
            info.ipc         = m.smoothed_ipc
            info.llc_miss    = m.smoothed_llc_miss
            info.ctx_freq    = m.smoothed_ctx_freq

        # Keep PIDs visible for 10s after last ring buffer entry
        # (idle processes stop appearing in ring buffer between samples)
        for pid in list(self.state.keys()):
            if not self.state[pid].seen:
                if now - self.state[pid].last_seen > 10.0:
                    del self.state[pid]

    def make_table(self):
        sort_key = {
            "cpu": lambda x: x.cpu_pct,
            "mem": lambda x: x.rss_mb,
            "ipc": lambda x: x.ipc,
        }.get(self.sort_by, lambda x: x.cpu_pct)

        rows = sorted(self.state.values(), key=sort_key, reverse=True)
        if self.top_n > 0:
            rows = rows[:self.top_n]

        conf_exists = os.path.exists(_CONF_PATH)
        shm_ok      = os.path.exists(SHM_PATH)
        src_str     = "[green]shm live[/]" if shm_ok else "[red]shm missing — start monitor_final[/]"
        cal_str     = "[green]calibrated[/]" if conf_exists else "[yellow]defaults[/]"

        table = Table(
            box=box.SIMPLE_HEAVY,
            title=(f"[bold cyan]Performance Monitor[/]  "
                   f"[dim]{time.strftime('%H:%M:%S')}[/]  "
                   f"{src_str}  thresholds:{cal_str}"),
            title_justify="left",
            show_header=True,
            header_style="bold white",
            border_style="bright_black",
            pad_edge=False,
        )
        table.add_column("PID",          style="cyan bold", width=7,  no_wrap=True)
        table.add_column("Process",      style="white",     width=18, no_wrap=True)
        table.add_column("CPU%",         style="green",     width=7,  justify="right")
        table.add_column("RSS(MB)",      style="blue",      width=8,  justify="right")
        table.add_column("Threads",      style="dim",       width=7,  justify="right")
        table.add_column("IPC",          style="yellow",    width=6,  justify="right")
        table.add_column("LLC%",         style="magenta",   width=8,  justify="right")
        table.add_column("ctx/s",        style="red",       width=10, justify="right")
        table.add_column("Est.Workload", width=12)
        # show Core column only when per-core data is present
        has_per_core = any(i.cpu_id >= 0 for i in rows)
        if has_per_core:
            table.add_column("Core", style="dim", width=5, justify="right")

        for info in rows:
            label, color = classify(info.ipc, info.llc_miss, info.ctx_freq)

            if info.cpu_pct > 80:
                cpu_str = f"[bold red]{info.cpu_pct:5.1f}[/]"
            elif info.cpu_pct > 40:
                cpu_str = f"[yellow]{info.cpu_pct:5.1f}[/]"
            else:
                cpu_str = f"{info.cpu_pct:5.1f}"

            _row = [
                str(info.pid),
                info.comm[:18],
                cpu_str,
                f"{info.rss_mb:6.1f}",
                str(info.threads),
                f"{info.ipc:.2f}",
                f"{info.llc_miss*100:.3f}",
                f"{info.ctx_freq:,.0f}",
                f"[{color}]{label}[/]",
            ]
            if has_per_core:
                _row.append(str(info.cpu_id) if info.cpu_id >= 0 else "agg")
            table.add_row(*_row)

        return Panel(
            table,
            title="[bold]Workload-Aware Linux Resource Monitor[/]",
            subtitle=f"[dim]{len(rows)} processes  |  sort:{self.sort_by}  |  Ctrl+C to exit[/]",
            border_style="cyan",
        )


# ── entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--top",      type=int,   default=20,
                        help="Max processes to display (default: 20)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Refresh interval in seconds (default: 2)")
    parser.add_argument("--sort",     default="cpu",
                        choices=["cpu", "mem", "ipc"],
                        help="Sort column (default: cpu)")
    args = parser.parse_args()

    console = Console()

    if not os.path.exists(SHM_PATH):
        console.print(f"[yellow]Waiting for {SHM_PATH} ...[/]")
        console.print("[dim]The daemon should start automatically. "
                      "Check: sudo systemctl status capstone_monitor[/]")

    if not os.path.exists(_CONF_PATH):
        console.print(f"[yellow]No calibration file found. Using default thresholds.[/]")
        console.print("[dim]Run: python3 calibrate.py  to calibrate for this machine[/]")
        time.sleep(2)

    dash = Dashboard(args.top, args.interval, args.sort)

    with Live(console=console, refresh_per_second=1, screen=True) as live:
        try:
            while True:
                dash.update()
                live.update(dash.make_table())
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass

    console.print("[cyan]Dashboard stopped.[/]")


if __name__ == "__main__":
    main()
