#!/usr/bin/env bash
# Produce the FULL combined contest disk for <arch> — both /musl and /glibc with
# every group, the exact ext4 image the contest grader mounts.
#
# Source order:
#   1) the OFFICIAL combined sdcard-<arch>.img.xz from the oscomp testsuite
#      release (this IS the contest image — fully faithful, no upload needed);
#   2) a mirror copy at $TEST_IMG_BASE/sdcard-<arch>.img, if present;
#   3) last resort: stitch the two LTP-only single-variant CI images into one
#      disk with /musl + /glibc — still runs musl→glibc in one boot, but lacks
#      the pre-LTP groups, so the accumulated-state trigger is weaker.
#
# Usage: prep-fulldisk.sh <rv|la> <out.img>
set -euo pipefail

ARCH="$1"
OUT="$2"
mkdir -p "$(dirname "$OUT")"

# Pinned to the pre-2025 final test images (what the pre-2025 contest stage
# mounts). Override with OSCOMP_FS_TAG for a different drop.
OSCOMP_TAG="${OSCOMP_FS_TAG:-pre-20250615}"
OSCOMP_URL="https://github.com/oscomp/testsuits-for-oskernel/releases/download/${OSCOMP_TAG}/sdcard-${ARCH}.img.xz"

# 1) Official combined image.
echo "[fulldisk] fetching official ${OSCOMP_TAG}/sdcard-${ARCH}.img.xz"
if curl -fSL --connect-timeout 20 --retry 3 --retry-delay 5 --max-time 1800 "$OSCOMP_URL" -o "$OUT.xz"; then
  echo "[fulldisk] decompressing ($(du -h "$OUT.xz" | cut -f1) compressed)"
  unxz -f "$OUT.xz"
  echo "[fulldisk] OFFICIAL combined disk ready: $OUT ($(du -h "$OUT" | cut -f1))"
  exit 0
fi
echo "::warning title=fulltest::official sdcard-${ARCH}.img.xz unavailable — falling back"

# 2) Mirror copy, if configured.
if [ -n "${TEST_IMG_BASE:-}" ] && \
   curl -fSL --connect-timeout 20 --retry 2 --retry-delay 5 \
        "${TEST_IMG_BASE%/}/sdcard-${ARCH}.img" -o "$OUT" 2>/dev/null; then
  echo "[fulldisk] using mirror combined sdcard-${ARCH}.img ($(du -h "$OUT" | cut -f1))"
  exit 0
fi

# 3) Stitch the two LTP-only single-variant CI images.
: "${TEST_IMG_BASE:?need official download or TEST_IMG_BASE for the stitch fallback}"
echo "[fulldisk] stitching single-variant images (LESS faithful: no basic/busybox/lua)"
echo "::warning title=fulltest::Stitched LTP-only variants — the accumulated-state pipe11 trigger may not reproduce. Official image preferred."
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
for libc in musl glibc; do
  v="$(mktemp "${RUNNER_TEMP:-/tmp}/var.XXXX.img")"
  curl -fSL --connect-timeout 20 --retry 3 --retry-delay 5 \
       "${TEST_IMG_BASE%/}/sdcard-${ARCH}-${libc}.img" -o "$v"
  m="$(mktemp -d)"
  sudo mount -o loop,ro "$v" "$m"
  sudo cp -a "$m/$libc" "$stage/$libc"   # single-variant tree lives under /<libc>/
  sudo umount "$m"; rmdir "$m"; rm -f "$v"
done
sudo chown -R "$(id -u):$(id -g)" "$stage"
mb=$(( $(du -sm "$stage" | cut -f1) + 256 ))
dd if=/dev/zero of="$OUT" bs=1M count="$mb" status=none
mke2fs -t ext4 -q -d "$stage" "$OUT" >/dev/null 2>&1
echo "[fulldisk] stitched $OUT ($(du -h "$OUT" | cut -f1)) with /musl + /glibc"
