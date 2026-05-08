CC     = gcc
CLANG  = clang
CFLAGS = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -Isrc

BUILD_DATE := $(shell date -Iseconds)
GIT_HASH   := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
CFLAGS += -DBUILD_DATE=\"$(BUILD_DATE)\" -DGIT_HASH=\"$(GIT_HASH)\"

LDFLAGS = -lbpf -lelf -lz -lrt

ARCH_INCLUDE := /usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS = -O2 -g -target bpf \
             $(if $(wildcard $(ARCH_INCLUDE)),-I$(ARCH_INCLUDE),)

SRCS = src/monitor_final.c \
       src/proc_scanner.c \
       src/perf_counter.c \
       src/ebpf_tracer.c \
       src/sliding_window.c \
       src/ring_buffer.c

PREFIX     ?= /opt/capstone_monitor
SYSTEMD_DIR ?= /etc/systemd/system

.PHONY: all clean bpf install uninstall

all: bpf monitor_final

bpf:
	@mkdir -p bpf
	$(CLANG) $(BPF_CFLAGS) -c bpf/ctx_switch.bpf.c -o bpf/ctx_switch.bpf.o

monitor_final: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install: all
	@echo "[install] Creating directories..."
	install -d $(DESTDIR)$(PREFIX)/bpf
	install -d $(DESTDIR)$(PREFIX)/scripts
	install -d $(DESTDIR)$(PREFIX)/tests
	
	@echo "[install] Installing binaries..."
	install -m 755 monitor_final $(DESTDIR)$(PREFIX)/
	install -m 644 bpf/ctx_switch.bpf.o $(DESTDIR)$(PREFIX)/bpf/
	
	@echo "[install] Installing scripts..."
	install -m 755 dashboard.py $(DESTDIR)$(PREFIX)/scripts/
	install -m 755 calibrate.py $(DESTDIR)$(PREFIX)/scripts/
	
	@echo "[install] Installing systemd service..."
	install -m 644 capstone_monitor.service $(DESTDIR)$(SYSTEMD_DIR)/
	
	@echo ""
	@echo "═══════════════════════════════════════════════════════"
	@echo "  Installation complete!"
	@echo ""
	@echo "  Next steps:"
	@echo "    1. Reload systemd:"
	@echo "       sudo systemctl daemon-reload"
	@echo ""
	@echo "    2. Calibrate thresholds (REQUIRED before first use):"
	@echo "       sudo python3 $(PREFIX)/scripts/calibrate.py --duration 30"
	@echo ""
	@echo "    3. Enable and start the daemon:"
	@echo "       sudo systemctl enable --now capstone_monitor"
	@echo ""
	@echo "    4. View live telemetry:"
	@echo "       python3 $(PREFIX)/scripts/dashboard.py"
	@echo ""
	@echo "    5. Check status:"
	@echo "       systemctl status capstone_monitor"
	@echo "       journalctl -u capstone_monitor -f"
	@echo "═══════════════════════════════════════════════════════"

uninstall:
	@echo "[uninstall] Stopping service..."
	-systemctl stop capstone_monitor 2>/dev/null || true
	-systemctl disable capstone_monitor 2>/dev/null || true
	@echo "[uninstall] Removing files..."
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/capstone_monitor.service
	rm -rf $(DESTDIR)$(PREFIX)
	@echo "[uninstall] Reloading systemd..."
	systemctl daemon-reload
	@echo "[uninstall] Done."

clean:
	rm -f monitor_final bpf/ctx_switch.bpf.o