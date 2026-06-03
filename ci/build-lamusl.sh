#!/usr/bin/env bash
# Reproducibly cross-build sdcard-la-musl.img — the full LTP syscall suite for
# loongarch64-musl — which has no packaged toolchain and isn't in any official
# combined sdcard split. Run locally, then upload the result to the
# 'test-images' release (the other 3 cells come from split-sdcard.sh).
#
# Requires:
#   MUSL_LA   dir of a loongarch64-linux-musl cross toolchain
#             (contains bin/loongarch64-linux-musl-gcc and
#              loongarch64-linux-musl/lib/libc.so)
#   BUSYBOX   a static musl-LoongArch busybox binary
#
# Usage: MUSL_LA=/opt/loongarch64-linux-musl BUSYBOX=/path/busybox \
#          ci/build-lamusl.sh [out.img]
set -euo pipefail

MUSL_LA="${MUSL_LA:?set MUSL_LA to the loongarch64-linux-musl toolchain dir}"
BUSYBOX="${BUSYBOX:?set BUSYBOX to a static musl-LoongArch busybox}"
OUT="$(realpath -m "${1:-sdcard-la-musl.img}")"
export PATH="$MUSL_LA/bin:$PATH"

W=$(mktemp -d); cd "$W"
git clone --depth 1 -b 20240524 https://github.com/linux-test-project/ltp.git ltp
cd ltp
make autotools
# musl defines `struct sysinfo` in <sys/sysinfo.h>; LTP also pulls the kernel
# UAPI <linux/sysinfo.h> (via tst_netlink.h), which redefines it. Pre-defining
# the kernel header's include guard makes musl's definition win.
./configure --host=loongarch64-linux-musl CC=loongarch64-linux-musl-gcc \
  CFLAGS="-O2 -fno-stack-protector -D_LINUX_SYSINFO_H"
make -C lib -j"$(nproc)"
# Build each syscall subdir independently so a glibc-only case (e.g. fmtmsg's
# addseverity, absent in musl) doesn't stop the whole recursive build.
for d in testcases/kernel/syscalls/*/; do make -C "$d" -k -j2 || true; done

S=$(mktemp -d); m="$S/musl"; mkdir -p "$m/ltp/testcases/bin" "$m/lib"
cp "$BUSYBOX" "$m/busybox"; chmod +x "$m/busybox"
cp "$MUSL_LA/loongarch64-linux-musl/lib/libc.so" "$m/lib/libc.so"
ln -sf libc.so "$m/lib/ld-musl-loongarch-lp64d.so.1"
ln -sf libc.so "$m/lib/ld-musl-loongarch64.so.1"
find testcases/kernel/syscalls -type f -perm -u+x | while read -r b; do
  case "$b" in *.sh|*.c|*.h|*.mk|*Makefile*|*.o) continue;; esac
  file -L "$b" 2>/dev/null | grep -q 'LoongArch' && cp "$b" "$m/ltp/testcases/bin/"
done
loongarch64-linux-musl-strip --strip-unneeded "$m"/ltp/testcases/bin/* 2>/dev/null || true
printf 'true\n' > "$m/ltp_testcode.sh"

mb=$(( $(du -sm "$S" | cut -f1) + 64 ))
dd if=/dev/zero of="$OUT" bs=1M count="$mb" status=none
mke2fs -t ext4 -q -d "$S" "$OUT" >/dev/null 2>&1
echo "wrote $OUT ($(du -h "$OUT" | cut -f1), $(ls "$m"/ltp/testcases/bin | wc -l) cases)"
