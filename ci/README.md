# CI — LTP quality control

`.github/workflows/ci.yml` (`ltp-ci`) builds the kernel and runs a curated LTP
sweep under QEMU across **4 cells**: `rv-musl`, `rv-glibc`, `la-musl`,
`la-glibc`. Triggered on push / PR / manual dispatch.

## How it fits in ~14 GB

Each matrix cell is an independent runner and handles **one** variant only:

- kernel build (cargo, cached in `cargo-<arch>-…`),
- **one** small test image — a curated LTP subset (`ci/ltp-cases.txt`), not the
  full ~2800-case suite — cached in `img-<cell>-…`,
- a 512 MiB sparse scratch disk (`/dev/sdb`) created at run time.

The job frees the runner's pre-installed bulk (dotnet, Android SDK, …) first.
Image caches stay small (subset → tens–hundreds of MB each), well under the
10 GB per-repo cache budget across all 4 cells.

## Image acquisition (in order)

1. **cache hit** → reuse (fast path; the common case).
2. **`TEST_IMAGE_BASE_URL` set** (repo secret or variable) → download
   `sdcard-<arch>-<libc>.img` — byte-for-byte what the grader runs
   (recommended; **required for `la-musl`**, see caveat).
3. **build from source** → clone upstream LTP `20240524`, cross-compile the
   subset, build a static busybox, assemble an ext2 image.

Toolchains for path 3: `rv-glibc`/`la-glibc` use the distro cross-gcc;
`rv-musl` pulls a musl cross from musl.cc.

### Caveat: `la-musl`

There is no packaged musl/LoongArch cross-toolchain, so `la-musl` **cannot
build from source** — it needs path 2 (`TEST_IMAGE_BASE_URL` with
`sdcard-la-musl.img`). The other three cells build from source out of the box.

## Pass/fail gate (`ci/parse-ltp.sh`)

A cell fails on any of: a kernel panic/exception, init (pid 1) being killed, an
ltp group that started but never ended, or the rc==0 case count dropping below
`ci/baseline/<cell>.txt`.

**Baselines** are not committed yet. After the first green run, read each cell's
"cases rc==0" from its log and commit it as `ci/baseline/<cell>.txt` (e.g.
`echo 57 > ci/baseline/rv-glibc.txt`). The gate then catches regressions; bump a
baseline deliberately when a cell legitimately improves (CI prints a notice when
it does).
