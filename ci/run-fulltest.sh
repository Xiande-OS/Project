#!/usr/bin/env bash
# Boot a kernel against the FULL combined contest disk (both /musl and /glibc,
# every group) in ONE QEMU instance — exactly as the contest grader runs each
# arch. This is the faithful counterpart to run-qemu.sh: that one boots a single
# LTP-only variant in isolation, so it can NEVER reproduce cross-variant or
# accumulated-state failures (e.g. an la-musl poweroff during ltp-musl taking
# the whole boot — and therefore la-glibc — to zero). Here musl runs first, then
# glibc, in the same kernel, like the contest.
#
# The QEMU command line mirrors the official contest spec: the test disk is x0
# on bus.0, our writable disk (the contest's disk.img, here a zeroed scratch the
# needs_device LTP cases mkfs as /dev/sdb) is x1 on bus.1, -no-reboot, -rtc utc.
#
# Usage: run-fulltest.sh <rv|la> <combined.img> <cell> [seconds] [mem] [smp]
set -euo pipefail

ARCH="$1"
IMG="$2"
CELL="$3"
SECS="${4:-14400}"   # 4 h wall cap; a poweroff/storm exits QEMU far sooner
MEM="${5:-1G}"
SMP="${6:-1}"

SCRATCH="$(mktemp -p "${RUNNER_TEMP:-/tmp}" scratch.XXXX.img)"
truncate -s 512M "$SCRATCH"
trap 'rm -f "$SCRATCH"' EXIT
LOG="$(mktemp)"

if [ "$ARCH" = "rv" ]; then
  timeout --signal=KILL "$SECS" \
    qemu-system-riscv64 -machine virt -kernel kernel-rv -m "$MEM" -nographic -smp "$SMP" \
      -bios default \
      -drive file="$IMG",if=none,format=raw,id=x0 \
      -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
      -no-reboot \
      -device virtio-net-device,netdev=net -netdev user,id=net \
      -rtc base=utc \
      -drive file="$SCRATCH",if=none,format=raw,id=x1 \
      -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1 \
      > "$LOG" 2>&1 || true
else
  # LA: virtio-pci. romfile= suppresses the PXE option ROM (absent in CI). The
  # net hostfwd on 5555 matches the official LA command.
  timeout --signal=KILL "$SECS" \
    qemu-system-loongarch64 -machine virt -kernel kernel-la -m "$MEM" -nographic -smp "$SMP" \
      -drive file="$IMG",if=none,format=raw,id=x0 \
      -device virtio-blk-pci,drive=x0 \
      -no-reboot \
      -device virtio-net-pci,netdev=net0,romfile= \
      -netdev user,id=net0,hostfwd=tcp::5555-:5555,hostfwd=udp::5555-:5555 \
      -rtc base=utc \
      -drive file="$SCRATCH",if=none,format=raw,id=x1 \
      -device virtio-blk-pci,drive=x1 \
      > "$LOG" 2>&1 || true
fi

cat "$LOG"
rm -f "$LOG"
