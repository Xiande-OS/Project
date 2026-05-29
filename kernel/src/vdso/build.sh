#!/bin/sh
# Regenerate the embedded riscv64 vDSO (vdso.so) from rt_sigreturn.S + vdso.lds.
#
# The kernel embeds the resulting vdso.so via include_bytes! (see
# kernel/src/vdso.rs) so the build is self-contained (no toolchain or
# network needed at kernel build time). Re-run this only when the
# rt_sigframe layout in kernel/src/signal.rs changes — the .cfi_* offsets
# in rt_sigreturn.S are tied to it (CFA = sp + 304 = &uc_mcontext.gregs,
# each saved x-reg at CFA + 8*greg_index).
#
# Uses the riscv toolchain from the contest docker image so the output is
# byte-reproducible regardless of the host. Run from this directory:
#   ./build.sh
set -eu

IMG=zhouzhouyi/os-contest:20260510
HERE=$(cd "$(dirname "$0")" && pwd)

docker run --rm -v "$HERE:/work" "$IMG" sh -c '
  set -eu
  cd /work
  riscv64-linux-gnu-gcc -c -o vdso.o rt_sigreturn.S \
    -nostdlib -fpic -march=rv64gc -mabi=lp64d
  riscv64-linux-gnu-ld -shared -soname=linux-vdso.so.1 \
    --hash-style=both --build-id=none -Bsymbolic \
    --eh-frame-hdr -z max-page-size=4096 \
    -T vdso.lds -o vdso.so vdso.o
  rm -f vdso.o
  echo "=== vdso.so ==="
  riscv64-linux-gnu-readelf -h vdso.so | grep -E "Type|program headers"
  riscv64-linux-gnu-readelf -sW --dyn-syms vdso.so | grep sigreturn
  echo "=== signal-frame CFI (must show Augmentation .zRS. + def_cfa r2 ofs 304) ==="
  riscv64-linux-gnu-readelf --debug-dump=frames vdso.so | head -8
'
echo "Done. Rebuild the kernel to embed the new vdso.so."
