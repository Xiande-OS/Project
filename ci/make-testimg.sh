#!/usr/bin/env bash
# Produce the per-cell LTP test image with the exact layout the in-kernel
# contest runner enumerates:
#
#   /<libc>/busybox                       (the shell the runner exec's)
#   /<libc>/ltp/testcases/bin/<case...>   (the test binaries)
#   /<libc>/ltp_testcode.sh               (drives the cases, prints markers)
#
# Two ways to obtain it, in order of preference:
#
#   1. DOWNLOAD a faithful prebuilt image (RECOMMENDED). Set repo secret/var
#      TEST_IMAGE_BASE_URL to a location holding
#         sdcard-<arch>-<libc>.img        e.g. .../sdcard-la-musl.img
#      These are byte-for-byte what the grader runs, so CI matches the contest
#      exactly. Build them once locally and host them (a GitHub Release on the
#      mirror works well); CI caches the result so the download happens rarely.
#
#   2. BUILD a curated subset from upstream LTP (ci/ltp-cases.txt) with the
#      cross-toolchain for the cell. Faithful for the glibc cells and rv-musl;
#      la-musl needs a musl-loongarch toolchain that isn't packaged, so that
#      cell falls back to requiring path (1).
#
# Usage: make-testimg.sh <rv|la> <musl|glibc> <out.img>
set -euo pipefail

ARCH="$1"; LIBC="$2"; OUT="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$(dirname "$OUT")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- 1. download a faithful prebuilt image, if configured --------------------
if [ -n "${TEST_IMAGE_URL:-}" ]; then
  url="${TEST_IMAGE_URL%/}/sdcard-${ARCH}-${LIBC}.img"
  echo "[img] trying prebuilt: $url"
  if curl -fSL --retry 3 --max-time 600 "$url" -o "$OUT"; then
    echo "[img] downloaded $(du -h "$OUT" | cut -f1)"
    exit 0
  fi
  echo "[img] download failed; falling back to source build"
fi

# ---- 2. pick a cross-toolchain ----------------------------------------------
# glibc cells use the distro cross-gcc; rv-musl pulls a musl cross; la-musl has
# no packaged musl toolchain → must use the download path above.
case "$ARCH-$LIBC" in
  rv-glibc) HOST=riscv64-linux-gnu;      CC=riscv64-linux-gnu-gcc ;;
  la-glibc) HOST=loongarch64-linux-gnu;  CC=loongarch64-linux-gnu-gcc-14 ;;
  rv-musl)
    echo "[tc] fetching riscv64 musl cross"
    curl -fSL --retry 3 https://musl.cc/riscv64-linux-musl-cross.tgz -o "$WORK/tc.tgz"
    tar -C "$WORK" -xf "$WORK/tc.tgz"
    export PATH="$WORK/riscv64-linux-musl-cross/bin:$PATH"
    HOST=riscv64-linux-musl; CC=riscv64-linux-musl-gcc ;;
  la-musl)
    echo "::error::la-musl has no packaged musl cross-toolchain."
    echo "::error::Set TEST_IMAGE_BASE_URL to host a prebuilt sdcard-la-musl.img (see ci/README.md)."
    exit 1 ;;
  *) echo "unknown cell $ARCH-$LIBC"; exit 2 ;;
esac
echo "[tc] $ARCH-$LIBC -> CC=$CC HOST=$HOST"

STAGE="$WORK/stage/$LIBC"
mkdir -p "$STAGE/ltp/testcases/bin"

# ---- 3. static busybox (the shell the kernel exec's) ------------------------
echo "[bb] building static busybox"
BB_VER=1.36.1
curl -fSL --retry 3 "https://busybox.net/downloads/busybox-${BB_VER}.tar.bz2" -o "$WORK/bb.tar.bz2"
tar -C "$WORK" -xf "$WORK/bb.tar.bz2"
( cd "$WORK/busybox-${BB_VER}"
  make defconfig >/dev/null 2>&1
  sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
  make -j"$(nproc)" CROSS_COMPILE="${CC%gcc}" CONFIG_STATIC=y busybox >/dev/null 2>&1 || true )
cp "$WORK/busybox-${BB_VER}/busybox" "$STAGE/busybox"
chmod +x "$STAGE/busybox"

# ---- 4. curated LTP subset --------------------------------------------------
echo "[ltp] cloning upstream LTP (tag 20240524)"
git clone --depth 1 -b 20240524 https://github.com/linux-test-project/ltp.git "$WORK/ltp" >/dev/null 2>&1
( cd "$WORK/ltp"
  make autotools >/dev/null 2>&1
  ./configure --host="$HOST" CC="$CC" CFLAGS="-O2 -fno-stack-protector" \
    LDFLAGS="-static" >/dev/null 2>&1
  make -C lib -j"$(nproc)" >/dev/null 2>&1 )
[ -f "$WORK/ltp/lib/libltp.a" ] || { echo "::error::libltp build failed"; exit 1; }

archpat='RISC-V'; [ "$ARCH" = la ] && archpat='LoongArch'
built=0
while read -r rel; do
  [ -z "$rel" ] && continue; case "$rel" in \#*) continue;; esac
  d="$WORK/ltp/testcases/kernel/syscalls/$(dirname "$rel")"
  [ -d "$d" ] || continue
  make -C "$d" -j2 >/dev/null 2>&1 || true
  b="$d/$(basename "$rel")"
  if [ -x "$b" ] && file -L "$b" 2>/dev/null | grep -q "$archpat"; then
    cp "$b" "$STAGE/ltp/testcases/bin/" && built=$((built+1))
  fi
done < "$HERE/ltp-cases.txt"
echo "[ltp] built $built case binaries"
[ "$built" -gt 0 ] || { echo "::error::no LTP cases built for $ARCH-$LIBC"; exit 1; }

# ---- 5. testcode runner (prints the markers the parser/grader match) --------
cat > "$STAGE/ltp_testcode.sh" <<RUN
#!/bin/busybox sh
echo "#### OS COMP TEST GROUP START ltp-$LIBC ####"
for f in ltp/testcases/bin/*; do
  [ -f "\$f" ] || continue
  n=\$(busybox basename "\$f")
  echo "RUN LTP CASE \$n"
  busybox setsid busybox timeout -s KILL 8 "\$f" < /dev/null
  echo "FAIL LTP CASE \$n : \$?"
done
echo "#### OS COMP TEST GROUP END ltp-$LIBC ####"
RUN
chmod +x "$STAGE/ltp_testcode.sh"

# ---- 6. lay down the ext2 image (small: subset only) ------------------------
SZMB=$(( $(du -sm "$WORK/stage" | cut -f1) + 64 ))
dd if=/dev/zero of="$OUT" bs=1M count="$SZMB" status=none
mke2fs -t ext4 -q -d "$WORK/stage" "$OUT" >/dev/null 2>&1
echo "[img] $OUT: $(du -h "$OUT" | cut -f1) ($built cases, $LIBC/$ARCH)"
