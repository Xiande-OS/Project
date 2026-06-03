#!/usr/bin/env bash
# Produce the FULL combined contest disk (both /musl and /glibc at the root) for
# <arch>, the way the contest serves it.
#
#   Faithful path: download the official combined sdcard-<arch>.img from the
#   test-images release — it carries every group (basic, busybox, lua, ltp, ...)
#   for both variants, exactly what the grader mounts.
#
#   Fallback: if that asset isn't uploaded yet, stitch the two LTP-only
#   single-variant images (sdcard-<arch>-musl.img + sdcard-<arch>-glibc.img,
#   already used by ci.yml) into one disk with /musl and /glibc. That still lets
#   fulltest observe the cross-variant interaction (musl then glibc in one boot)
#   but lacks the pre-LTP groups, so it is strictly less faithful.
#
# Usage: prep-fulldisk.sh <rv|la> <out.img>
set -euo pipefail

ARCH="$1"
OUT="$2"
BASE="${TEST_IMG_BASE:?TEST_IMG_BASE is not set}"
mkdir -p "$(dirname "$OUT")"

# 1) Faithful path — the official combined image.
if curl -fSL --connect-timeout 20 --retry 2 --retry-delay 5 \
        "${BASE%/}/sdcard-${ARCH}.img" -o "$OUT" 2>/dev/null; then
  echo "[fulldisk] using official combined sdcard-${ARCH}.img ($(du -h "$OUT" | cut -f1))"
  exit 0
fi

echo "[fulldisk] sdcard-${ARCH}.img not found in release — stitching single-variant images"
echo "::warning title=fulltest::Using STITCHED LTP-only variants (no basic/busybox/lua). Upload the official sdcard-${ARCH}.img to the test-images release for a fully faithful run."

# 2) Fallback — stitch the two LTP-only single-variant images.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
for libc in musl glibc; do
  v="$(mktemp "${RUNNER_TEMP:-/tmp}/var.XXXX.img")"
  curl -fSL --connect-timeout 20 --retry 3 --retry-delay 5 \
       "${BASE%/}/sdcard-${ARCH}-${libc}.img" -o "$v"
  m="$(mktemp -d)"
  sudo mount -o loop,ro "$v" "$m"
  # Each single-variant image holds its tree under /<libc>/ (see split-sdcard.sh).
  sudo cp -a "$m/$libc" "$stage/$libc"
  sudo umount "$m"; rmdir "$m"; rm -f "$v"
done
sudo chown -R "$(id -u):$(id -g)" "$stage"

mb=$(( $(du -sm "$stage" | cut -f1) + 256 ))
dd if=/dev/zero of="$OUT" bs=1M count="$mb" status=none
mke2fs -t ext4 -q -d "$stage" "$OUT" >/dev/null 2>&1
echo "[fulldisk] stitched $OUT ($(du -h "$OUT" | cut -f1)) with /musl + /glibc"
