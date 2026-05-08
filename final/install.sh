#!/bin/bash
# =============================================================================
# One-command installer for capstone_monitor
#
# Usage:
#   git clone https://github.com/group4/capstone_monitor.git
#   cd capstone_monitor/final
#   sudo ./install.sh
#
# This script:
#   1. Checks for required dependencies
#   2. Builds the daemon and eBPF program
#   3. Installs everything to /opt/capstone_monitor/
#   4. Installs and enables the systemd service
#   5. Runs calibration
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Capstone Monitor — One-Command Installer${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""

# ── Root check ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: This script must be run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# ── Dependency check ───────────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking dependencies...${NC}"

MISSING=""
for cmd in gcc clang make python3; do
    if ! command -v $cmd &>/dev/null; then
        MISSING="$MISSING $cmd"
    fi
done

for pkg in libbpf-dev libelf-dev zlib1g-dev; do
    if ! dpkg -s $pkg &>/dev/null 2>&1; then
        MISSING="$MISSING $pkg"
    fi
done

if [[ -n "$MISSING" ]]; then
    echo -e "${RED}Missing dependencies:$MISSING${NC}"
    echo ""
    echo "Install them with:"
    echo "  sudo apt update"
    echo "  sudo apt install -y gcc clang make python3 libbpf-dev libelf-dev zlib1g-dev linux-headers-\$(uname -r)"
    echo ""
    echo "For Python dashboard:"
    echo "  pip3 install rich"
    exit 1
fi
echo -e "${GREEN}  All dependencies found.${NC}"

# ── Build ───────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Building daemon and eBPF program...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
make clean
make all
echo -e "${GREEN}  Build complete.${NC}"

# ── Install ─────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/5] Installing to /opt/capstone_monitor/...${NC}"
make install
echo -e "${GREEN}  Files installed.${NC}"

# ── Calibrate ───────────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/5] Running calibration (30 seconds per workload)...${NC}"
echo "  This runs CPU, memory, and I/O workloads to determine"
echo "  optimal classification thresholds for this machine."
echo ""

# Calibrate needs sysbench and stress-ng — check and offer to install
for tool in sysbench stress-ng; do
    if ! command -v $tool &>/dev/null; then
        echo -e "${YELLOW}  $tool not found. Installing...${NC}"
        apt-get install -y $tool 2>/dev/null || {
            echo -e "${RED}  Failed to install $tool. Skipping calibration.${NC}"
            echo "  Run manually later: sudo python3 /opt/capstone_monitor/scripts/calibrate.py"
            exit 0
        }
    fi
done

python3 /opt/capstone_monitor/scripts/calibrate.py --duration 30
echo -e "${GREEN}  Calibration complete.${NC}"

# ── Enable service ──────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Enabling systemd service...${NC}"
systemctl daemon-reload
systemctl enable --now capstone_monitor
sleep 2

# Check if the service started successfully
if systemctl is-active --quiet capstone_monitor; then
    echo -e "${GREEN}  Service is running.${NC}"
else
    echo -e "${RED}  Service failed to start. Check logs:${NC}"
    echo "    journalctl -u capstone_monitor --since '1 min ago'"
    exit 1
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  View live dashboard:"
echo "    python3 /opt/capstone_monitor/scripts/dashboard.py"
echo ""
echo "  View daemon logs:"
echo "    journalctl -u capstone_monitor -f"
echo ""
echo "  Check for ring buffer drops (should be 0):"
echo "    journalctl -u capstone_monitor | grep drops"
echo ""
echo "  Stop the daemon:"
echo "    sudo systemctl stop capstone_monitor"
echo ""
echo "  Uninstall:"
echo "    sudo make -C $(pwd) uninstall"
echo ""