# Capstone Monitor — Real-Time Performance Monitoring Daemon

A low-overhead (**<5% CPU**) Linux performance monitoring daemon that collects
hardware performance counters (IPC, LLC miss rate) and software events
(context switches, block I/O) per process, then exports smoothed metrics
via a lock-free shared-memory ring buffer for workload classification.

Part of the **"Workload-Aware Linux Resource Management Framework"** capstone project.

---

## Architecture

```
┌─────────────┐  perf_event_open  ┌────────────────┐
│  Linux PMU  │◄──────────────────│ monitor_final  │
│  eBPF progs │◄── bpf() syscall ─│  (C daemon)    │
└─────────────┘                   │                │
                                  │  ┌──────────┐  │
                                  │  │ Sliding  │  │
                                  │  │ Windows  │  │
                                  │  └────┬─────┘  │
                                  │       │        │
                                  │  ┌────▼─────┐  │
                                  │  │  Ring    │  │
                                  │  │  Buffer  │  │
                                  │  │  (shm)   │  │
                                  │  └────┬─────┘  │
                                  └───────┼────────┘
                                          │
             ┌────────────────────────────┼─────────────────────────┐
             │                            │                         │
  ┌──────────▼──────┐           ┌─────────▼────────┐         ┌──────▼──────┐
  │   Classifier    │           │    Dashboard     │         │ ghOSt Agent │
  │  (C / Python)   │           │    (Python)      │         │    (C)      │
  └─────────────────┘           └──────────────────┘         └─────────────┘
```

---

## Quick Install

```bash
git clone https://github.com/Reedam-Shrestha/capstone_monitor.git
cd capstone_monitor/final
sudo ./install.sh
```

> Builds, installs, calibrates thresholds, and starts the daemon in **one command**.

---

## Manual Install

### 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y gcc clang make python3 libbpf-dev libelf-dev zlib1g-dev \
                    linux-headers-$(uname -r) sysbench stress-ng
pip3 install rich
```

### 2. Build

```bash
make clean && make
```

### 3. Install

```bash
sudo make install
sudo systemctl daemon-reload
```

### 4. Calibrate *(REQUIRED)*

```bash
sudo python3 /opt/capstone_monitor/scripts/calibrate.py --duration 30
```

### 5. Start

```bash
sudo systemctl enable --now capstone_monitor
```

---

## Usage

```bash
# View live dashboard
python3 /opt/capstone_monitor/scripts/dashboard.py

# View daemon logs
journalctl -u capstone_monitor -f

# Run manually (stop the service first)
sudo systemctl stop capstone_monitor
sudo /opt/capstone_monitor/monitor_final /opt/capstone_monitor/bpf/ctx_switch.bpf.o \
    --top 20 --terminal

# Measure overhead
sudo ./tests/validate_overhead.sh 60

# Recalibrate after hardware changes
sudo python3 /opt/capstone_monitor/scripts/calibrate.py --duration 30
```

---

## CLI Options

| Flag | Description |
|------|-------------|
| `--top N` | Monitor top N processes by CPU (default: 50) |
| `--pids P1,P2` | Monitor specific PIDs |
| `--all` | Monitor all user processes |
| `--interval MS` | Sample interval in ms (default: 50) |
| `--csv FILE` | Write raw samples to CSV |
| `--per-core` | Enable per-core counter tracking |
| `--cores N,M` | Monitor only specific cores |
| `--terminal` | Print live table to terminal |
| `--quiet` | Suppress non-error output |
| `--version` | Print build info and exit |

---

## File Structure

```
Capstone-monitor/
└── final/
    ├── Makefile                       # Build system
    ├── install.sh                     # One-command installer (chmod +x)
    ├── README.md                      # This file
    ├── dashboard.py                   # Rich terminal dashboard
    ├── calibrate.py                   # Auto-calibration script
    ├── capstone_monitor.service       # systemd unit file
    ├── src/
    │   ├── monitor_final.c            # Main daemon
    │   ├── monitor_final.h
    │   ├── perf_counter.c             # perf_event_open wrapper
    │   ├── perf_counter.h
    │   ├── ebpf_tracer.c              # libbpf wrapper
    │   ├── ebpf_tracer.h
    │   ├── proc_scanner.c             # /proc PID scanner
    │   ├── proc_scanner.h
    │   ├── ring_buffer.c              # Lock-free SPSC ring buffer
    │   ├── ring_buffer.h
    │   ├── sliding_window.c           # Sliding window aggregation
    │   ├── sliding_window.h
    │   └── smoothed_metrics.h         # Shared struct definition
    ├── bpf/
    │   └── ctx_switch.bpf.c           # eBPF program
    └── tests/
        └── validate_overhead.sh       # Overhead measurement script
```

---

## Push to GitHub

```bash
cd Capstone-monitor
git add final/Makefile final/install.sh final/README.md final/tests/
git commit -m "Add build system, installer, and documentation"
git push
```

---

## Installing From GitHub

After pushing, anyone can install with:

```bash
git clone https://github.com/Reedam-Shrestha/capstone_monitor.git
cd capstone_monitor/final
sudo ./install.sh
```

---

## systemd Service

The service unit uses `Type=notify`. Ensure the `ExecStart` line in
`capstone_monitor.service` reads:

```ini
ExecStart=/opt/capstone_monitor/monitor_final /opt/capstone_monitor/bpf/ctx_switch.bpf.o \
    --all --top 50 --interval 50 --quiet
```

> The `--quiet` flag keeps the journal clean in production.

---

## Uninstall

```bash
sudo make uninstall
```
