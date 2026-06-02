#!/usr/bin/env bash
# Turn an OFFICIAL combined sdcard image (which has /musl and /glibc variant
# trees at its root) into the per-cell, LTP-only images CI downloads:
#
#   sdcard-<arch>-musl.img   sdcard-<arch>-glibc.img
#
# Each keeps just that variant's busybox + lib + ltp/ tree (the in-kernel runner
# generates its own ltp driver, so a `ltp_testcode.sh` trigger is enough).
# Upload the resulting files to the 'test-images' release on the mirror.
#
# Run locally (NOT in CI). Usage:
#   sudo ./split-sdcard.sh <rv|la> <official-sdcard.img> [outdir]
# Requires: sudo (loop mount) + e2fsprogs (mke2fs).
set -euo pipefail

ARCH="$1"; SRC="$2"; OUT="${3:-.}"
[ "$ARCH" = rv ] || [ "$ARCH" = la ] || { echo "arch must be rv|la"; exit 2; }

mnt=$(mktemp -d)
mount -o loop,ro "$SRC" "$mnt"
trap 'umount "$mnt" 2>/dev/null; rmdir "$mnt" 2>/dev/null || true' EXIT

for libc in musl glibc; do
  src="$mnt/$libc"
  if [ ! -d "$src/ltp/testcases/bin" ]; then
    echo "skip $libc — no ltp/testcases/bin in $SRC"; continue
  fi
  stage=$(mktemp -d); d="$stage/$libc"; mkdir -p "$d/ltp"
  cp -a "$src/busybox" "$d/busybox" 2>/dev/null || true
  [ -d "$src/lib" ] && cp -a "$src/lib" "$d/lib"
  cp -a "$src/ltp/." "$d/ltp/"
  [ -f "$d/ltp_testcode.sh" ] || printf 'true\n' > "$d/ltp_testcode.sh"
  img="$OUT/sdcard-$ARCH-$libc.img"
  mb=$(( $(du -sm "$stage" | cut -f1) + 64 ))
  dd if=/dev/zero of="$img" bs=1M count="$mb" status=none
  mke2fs -t ext4 -q -d "$stage" "$img" >/dev/null 2>&1
  rm -rf "$stage"
  echo "wrote $img  ($(du -h "$img" | cut -f1), $(ls "$src/ltp/testcases/bin" | wc -l) cases)"
done
echo "Upload the sdcard-$ARCH-*.img files to:"
echo "  https://github.com/Xiande-OS/Project/releases/tag/test-images"
