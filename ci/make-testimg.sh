#!/usr/bin/env bash
# Fetch the per-cell full-LTP test image from the Releases CDN.
#
# Images are PREBUILT and uploaded to the 'test-images' release — CI does not
# build them (building in-runner hung on flaky third-party mirrors). Expected
# asset name: sdcard-<arch>-<libc>.img  (e.g. sdcard-la-musl.img), each a single
# variant's full tree the in-kernel runner enumerates under /<libc>/.
#
# Usage: make-testimg.sh <rv|la> <musl|glibc> <out.img>
set -euo pipefail

ARCH="$1"; LIBC="$2"; OUT="$3"
BASE="${TEST_IMG_BASE:?TEST_IMG_BASE is not set}"
url="${BASE%/}/sdcard-${ARCH}-${LIBC}.img"
mkdir -p "$(dirname "$OUT")"

echo "[img] downloading $url"
# Short connect timeout → a missing asset errors in seconds, not minutes (the
# old from-source path sat on a dead musl.cc socket for 135s). Retries only
# cover transient CDN blips.
if ! curl -fSL --connect-timeout 20 --retry 3 --retry-delay 5 --max-time 1800 "$url" -o "$OUT"; then
  echo "::error title=${ARCH}-${LIBC}::test image not found: $url"
  echo "::error::Upload sdcard-${ARCH}-${LIBC}.img to the 'test-images' release (see ci/README.md)."
  exit 1
fi
echo "[img] got $(du -h "$OUT" | cut -f1)"
