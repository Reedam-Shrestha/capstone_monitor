#!/usr/bin/env python3
"""
calibrate.py — Runs workloads and uses monitor_final's explicit --pids mode
to record data directly to CSV, bypassing the shared memory buffer entirely.
"""

import os, sys, time, argparse, subprocess, statistics, pwd, csv
from pathlib import Path

# Resolve paths
SCRIPT_DIR  = Path(__file__).parent.resolve()
INSTALL_DIR = SCRIPT_DIR.parent           # /opt/capstone_monitor/
MONITOR_BIN = INSTALL_DIR / "monitor_final"
BPF_OBJ     = INSTALL_DIR / "bpf" / "ctx_switch.bpf.o"

SUDO_USER = os.environ.get("SUDO_USER")
if SUDO_USER:
    REAL_HOME = Path(pwd.getpwnam(SUDO_USER).pw_dir)
else:
    REAL_HOME = Path.home()

CONF_PATH = REAL_HOME / ".config" / "capstone-monitor" / "thresholds.conf"

def get_all_target_pids(base_pid):
    targets = {base_pid}
    
    # 1. Grab all POSIX threads (TIDs) for this process (Crucial for Sysbench)
    try:
        tasks = os.listdir(f"/proc/{base_pid}/task")
        for t in tasks: 
            targets.add(int(t))
    except FileNotFoundError: 
        pass

    # 2. Grab all child processes (Crucial for stress-ng)
    try:
        out = subprocess.check_output(['pgrep', '-P', str(base_pid)], stderr=subprocess.DEVNULL)
        for c in out.decode().split():
            targets.update(get_all_target_pids(int(c)))
    except subprocess.CalledProcessError: 
        pass
        
    return targets

def wrap_cmd(cmd_list):
    if SUDO_USER:
        return ["sudo", "-u", SUDO_USER] + cmd_list
    return cmd_list

def run_cpu():
    return subprocess.Popen(wrap_cmd(["sysbench", "cpu", "--time=60", "--threads=1", "run"]),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_mem():
    # Allocating 1GB forces the CPU to miss the cache and hit physical RAM. 
    # This guarantees a drop in IPC and a massive spike in LLC Misses.
    return subprocess.Popen(
        wrap_cmd(["stress-ng", "--vm", "1", "--vm-bytes", "1G", "--timeout", "60s"]),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

def run_io():
    return subprocess.Popen(wrap_cmd(["stress-ng", "--io", "1", "--timeout", "60s"]),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_workload_and_trace(name, launcher_func, duration):
    print(f"── {name} workload ──────────────────────────")
    try:
        p_work = launcher_func()
    except FileNotFoundError as e:
        print(f"  SKIP: {e} (tool not installed)")
        return {"ipc": 0.0, "llc": 0.0, "ctx": 0.0, "n": 0}

    print(f"  Launched workload PID {p_work.pid}")
    
    # Give sysbench time to fully spawn its worker threads
    time.sleep(2.0) 

    # Gather all worker PIDs & TIDs
    pids = get_all_target_pids(p_work.pid)
    pid_str = ",".join(map(str, pids))
    csv_path = SCRIPT_DIR / f"{name}_calib.csv"

    print(f"  Tracing threads/PIDs: {pid_str} (Directly via C-Daemon)")

    # Launch daemon strictly targeting these PIDs -> bypassing proc_scanner
    monitor_cmd = [str(MONITOR_BIN), str(BPF_OBJ), "--pids", pid_str, "--csv", str(csv_path), "--interval", "50"]
    p_mon = subprocess.Popen(monitor_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Collect data for specified duration
    time.sleep(duration)

    # Cleanly terminate daemon so it flushes the CSV file
    p_mon.terminate()
    p_mon.wait()
    p_work.terminate()
    p_work.wait()

    # Read the results directly from the CSV
    ipc, llc, ctx = [], [], []
    if csv_path.exists():
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ipc.append(float(row['ipc']))
                llc.append(float(row['llc_miss']))
                ctx.append(float(row['ctx_freq']))
        csv_path.unlink() # Cleanup temporary CSV

    n = len(ipc)
    if n == 0:
        print("  WARNING: No samples collected.")
        return {"ipc": 0.0, "llc": 0.0, "ctx": 0.0, "n": 0}

    res = {
        "ipc": statistics.mean(ipc),
        "llc": statistics.mean(llc),
        "ctx": statistics.mean(ctx),
        "n":   n,
    }
    
    print(f"  Result: ipc={res['ipc']:.3f}  llc={res['llc']:.5f}  ctx={res['ctx']:.1f}  n={res['n']}\n")
    return res


def get_hardware_specs():
    """Reads Linux procfs to dynamically determine Core Count and RAM."""
    # 1. Get Logical Cores
    cores = os.cpu_count() or 2
    
    # 2. Get Total RAM in GB
    ram_gb = 8 # Default fallback
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if 'MemTotal' in line:
                    kb = int(line.split()[1])
                    ram_gb = round(kb / (1024**2))
                    break
    except Exception:
        pass
    
    # Clamp RAM to avoid zero-division on weird systems
    ram_gb = max(ram_gb, 1)
    return cores, ram_gb


def derive_thresholds(cpu_res, mem_res, io_res):
    cores, ram_gb = get_hardware_specs()
    print(f"\n[calibrate] Hardware Detected: {cores} Cores, ~{ram_gb} GB RAM")
    
    # ── 1. Calculate Hardware Baselines ──────────────────────────────────────
    # IPC CPU Formula: 2 cores -> 1.2 | 8 cores -> 2.0
    # Equation: 1.2 + (cores - 2) * ((2.0 - 1.2) / (8 - 2))
    hw_cpu_ipc = 1.2 + max(0, (cores - 2)) * 0.1333
    hw_cpu_ipc = min(hw_cpu_ipc, 3.0) # Cap at 3.0 for massive servers
    
    # LLC MEM Formula: 8GB -> 0.02 | scales inversely with RAM
    hw_mem_llc = 0.02 * (8.0 / ram_gb)
    
    print(f"[calibrate] HW Base Estimates : CPU IPC={hw_cpu_ipc:.2f}, LLC={hw_mem_llc:.4f}")

    # ── 2. Extract Benchmark Results ─────────────────────────────────────────
    raw_c_ipc = cpu_res["ipc"] if cpu_res["n"] > 0 else 1.0
    raw_m_ipc = mem_res["ipc"] if mem_res["n"] > 0 else 0.5
    raw_m_llc = mem_res["llc"] if mem_res["n"] > 0 else 0.0
    raw_i_ctx = io_res["ctx"]  if io_res["n"] > 0 else 1000.0

    # ── 3. Hybrid Calculation (Hardware + Benchmark) ─────────────────────────
    
    # Scale benchmark data to simulate real-world tasks
    est_c_ipc = raw_c_ipc * 2.0 
    est_m_ipc = raw_m_ipc * 0.5 

    # IPC Threshold: 
    # Take the benchmark calculation, but NEVER drop below the Hardware Baseline!
    calc_cpu_thresh = (est_c_ipc + est_m_ipc) / 2.0
    ipc_cpu_thresh = max(calc_cpu_thresh, hw_cpu_ipc)
    
    # Memory IPC is just slightly below the scaled memory estimate
    ipc_mem_thresh = est_m_ipc * 0.9
    
    # LLC Threshold:
    # Take benchmark data, but NEVER drop below the Hardware RAM Baseline!
    calc_llc_thresh = raw_m_llc * 0.5
    llc_mem_thresh = max(calc_llc_thresh, hw_mem_llc)
    
    # IO Threshold: Context switches scale strictly with disk/OS speed, 
    # so we rely 100% on the benchmark for this.
    ctx_io_thresh  = raw_i_ctx * 0.5

    return {
        "ipc_cpu_threshold": round(ipc_cpu_thresh, 4),
        "ipc_mem_threshold": round(ipc_mem_thresh, 4),
        "llc_mem_threshold": round(llc_mem_thresh, 6),
        "ctx_io_threshold":  round(ctx_io_thresh,  1),
    }
    
def write_thresholds(thresholds: dict):
    CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONF_PATH, "w") as f:
        f.write("# Auto-generated by direct-trace calibrate.py\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for k, v in thresholds.items():
            f.write(f"{k} = {v}\n")
    
    if SUDO_USER:
        uid = pwd.getpwnam(SUDO_USER).pw_uid
        gid = pwd.getpwnam(SUDO_USER).pw_gid
        os.chown(CONF_PATH, uid, gid)
        os.chown(CONF_PATH.parent, uid, gid)
    print(f"[calibrate] Thresholds written to {CONF_PATH}")

def main():
    parser = argparse.ArgumentParser(description="Calibrate workload thresholds via direct C-daemon tracing.")
    parser.add_argument("--duration", type=float, default=15.0)
    args = parser.parse_args()

    if not MONITOR_BIN.exists():
        print(f"[calibrate] ERROR: {MONITOR_BIN} not found! Please run 'make' first.", file=sys.stderr)
        sys.exit(1)

    print("Stopping background systemd daemon (to avoid shared memory collisions)...")
    subprocess.run(["systemctl", "stop", "capstone-monitor"], stderr=subprocess.DEVNULL)

    print("\nStarting Direct-Trace Calibration...\n")
    results = {}
    workloads = [("CPU", run_cpu), ("MEM", run_mem), ("IO", run_io)]

    for name, launcher in workloads:
        results[name] = run_workload_and_trace(name, launcher, args.duration)

    thresholds = derive_thresholds(results["CPU"], results["MEM"], results["IO"])

    print("── Derived thresholds ───────────────────────")
    for k, v in thresholds.items():
        print(f"  {k:30s} = {v}")

    write_thresholds(thresholds)

    print("\nRestarting background systemd daemon...")
    subprocess.run(["systemctl", "start", "capstone-monitor"], stderr=subprocess.DEVNULL)

if __name__ == "__main__":
    main()
