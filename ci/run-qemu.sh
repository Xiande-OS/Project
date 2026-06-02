#!/usr/bin/env bash
# Boot a built kernel against a test image under QEMU and capture the serial
# log. Arch-specific machine/devices mirror exactly what the contest grader
# uses (see README "Run"): RV = virt + virtio-mmio, LA = virt + virtio-pci.
#
# A second, zeroed virtio-blk device is attached as the writable scratch
# (/dev/sdb) the `.needs_device` LTP cases mkfs+mount — the in-kernel ext2
# mkfs formats it at first use.
#
# Usage: run-qemu.sh <rv|la> <image.img> <cell-name> [seconds]
set -euo pipefail

ARCH="$1"
IMG="$2"
CELL="$3"
SECS="${4:-600}"

SCRATCH="$(mktemp -p "${RUNNER_TEMP:-/tmp}" scratch.XXXX.img)"
# 512 MiB sparse scratch — instant, costs no real disk until written.
truncate -s 512M "$SCRATCH"
trap 'rm -f "$SCRATCH"' EXIT

LOG="$(mktemp)"

if [ "$ARCH" = "rv" ]; then
  timeout --signal=KILL "$SECS" \
    qemu-system-riscv64 -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 \
      -bios default \
      -drive file="$IMG",if=none,format=raw,id=x0 \
      -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
      -drive file="$SCRATCH",if=none,format=raw,id=x1 \
      -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1 \
      -no-reboot \
      -device virtio-net-device,netdev=net -netdev user,id=net \
      -rtc base=utc > "$LOG" 2>&1 || true
else
  timeout --signal=KILL "$SECS" \
    qemu-system-loongarch64 -machine virt -kernel kernel-la -m 1G -nographic -smp 1 \
      -drive file="$IMG",if=none,format=raw,id=x0 \
      -device virtio-blk-pci,drive=x0 \
      -drive file="$SCRATCH",if=none,format=raw,id=x1 \
      -device virtio-blk-pci,drive=x1 \
      -no-reboot \
      -device virtio-net-pci,netdev=net,romfile= -netdev user,id=net \
      -rtc base=utc > "$LOG" 2>&1 || true
fi

# Emit the captured log to stdout (the workflow tees it to ci/<cell>.log).
cat "$LOG"
rm -f "$LOG"
