#!/bin/bash
# Run kernel-rv against a mini disk image, with a tight wall-clock cap.
#
# Usage: run-mini.sh <disk.img> [seconds]
#   default seconds = 20

set -euo pipefail

IMG="$1"
SEC="${2:-20}"

LOG=$(mktemp)
trap "rm -f $LOG" EXIT

timeout "$SEC" qemu-system-riscv64 -machine virt \
    -kernel kernel-rv -m 512M -nographic -smp 1 -bios default \
    -drive file="$IMG",if=none,format=raw,id=x0 \
    -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot \
    -device virtio-net-device,netdev=net -netdev user,id=net \
    -rtc base=utc > "$LOG" 2>&1 || true

# Print everything from the contest init line onward, filtering out
# the noisy [sys ...] trace and [openat ...] debug prints. Keep
# [exit ...] because tests rely on its presence/absence.
sed -n '/contest init/,$p' "$LOG" \
    | grep -vE '^\[sys |^\[openat |^\[execve |^\[nanosleep '
