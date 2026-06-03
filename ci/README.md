# CI — LTP quality control

`.github/workflows/ci.yml` (`ltp-ci`) builds the kernel and runs the **full LTP
suite** under QEMU across **4 cells**: `rv-musl`, `rv-glibc`, `la-musl`,
`la-glibc`. Triggered on push / PR / manual dispatch.

## Test images (you provide these)

CI does **not** build test images (building LTP in the runner hung on flaky
third-party mirrors). Instead each cell **downloads a prebuilt full-suite image**
from the `test-images` release on the mirror:

    https://github.com/Xiande-OS/Project/releases/tag/test-images

Expected assets — one single-variant image per cell:

    sdcard-rv-musl.img   sdcard-rv-glibc.img
    sdcard-la-musl.img   sdcard-la-glibc.img

Each holds that variant's `busybox` + `lib/` + `ltp/` tree under `/<libc>/` (the
in-kernel runner generates its own ltp driver, so a `ltp_testcode.sh` trigger is
enough).

## Test images (already uploaded)

All four cell images are present in the `test-images` release, so CI runs
out of the box. How each was produced, for when they need rebuilding:

- `rv-musl`, `rv-glibc`, `la-glibc` — split from the official combined per-arch
  sdcards with `ci/split-sdcard.sh` (each official image has both `/musl` and
  `/glibc`):

      sudo ci/split-sdcard.sh rv  /path/sdcard-rv.img  ./out
      sudo ci/split-sdcard.sh la  /path/sdcard-la.img  ./out

- `la-musl` — has no packaged toolchain and isn't in any official split, so it
  is cross-built from upstream LTP with `ci/build-lamusl.sh` (needs a
  loongarch64-linux-musl toolchain + a static musl-LA busybox):

      MUSL_LA=/opt/loongarch64-linux-musl BUSYBOX=/path/busybox \
        ci/build-lamusl.sh sdcard-la-musl.img

Upload the produced `sdcard-<arch>-<libc>.img` files to the release, then bump
`IMG_VERSION` in `ci.yml` to refresh the per-cell image cache.

## How it works per cell

1. build the kernel (cargo `--offline` with the vendored crates; cached in
   `cargo-<arch>-…`),
2. download the cell's image (cached in `img-<cell>-<IMG_VERSION>`; the download
   runs only on a cache miss),
3. boot it under QEMU exactly as the grader does (RV virtio-mmio, LA virtio-pci)
   with a 512 MiB scratch `/dev/sdb` for `.needs_device` cases, full-suite wall
   cap 2700 s (the in-kernel ltp budget ~2000 s governs),
4. parse + gate (`ci/parse-ltp.sh`).

Runner disk (~14 GB) is fine: one single-variant image per cell, the runner's
pre-installed bulk freed first. Image caches (one per cell) stay under the 10 GB
per-repo cache budget.

## Pass/fail gate (`ci/parse-ltp.sh`)

A cell fails on any of: a kernel panic/exception, init (pid 1) being killed, an
ltp group that started but never ended, or the rc==0 case count dropping below
`ci/baseline/<cell>.txt`.

**Baselines** are not committed yet. After the first green run, read each cell's
"cases rc==0" from its log and commit it as `ci/baseline/<cell>.txt` (e.g.
`echo 1771 > ci/baseline/rv-glibc.txt`). The gate then catches regressions; bump
a baseline deliberately when a cell legitimately improves (CI prints a notice
when it does).
