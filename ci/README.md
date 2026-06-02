# CI — LTP quality control

Two workflows under `.github/workflows/`:

| workflow | trigger | what it does |
|---|---|---|
| `ci.yml` (`ltp-ci`) | push / PR / manual | build the kernel and run a curated LTP sweep under QEMU, across **4 cells**: `rv-musl`, `rv-glibc`, `la-musl`, `la-glibc` |
| `mirror.yml` (`mirror`) | push | mirror the pushed ref to `Xiande-OS/Project` |

## One-time setup (must be done in the GitHub UI)

1. **`MIRROR_TOKEN` secret** — `fangliding/xiande-os` → *Settings → Secrets and
   variables → Actions → New repository secret*:
   - Name: `MIRROR_TOKEN`
   - Value: a PAT for the `Xiande-OS` account with `repo` (write) scope on
     `Xiande-OS/Project`.
   - The token lives **only** here. It is never written into any file in the
     repo. The `mirror` job reads it as `${{ secrets.MIRROR_TOKEN }}`.
   - ⚠️ **Rotate the token that was shared in chat** — assume it is compromised.
     Generate a fresh one, put the fresh one in this secret, revoke the old one.

2. **Enable Actions on the mirror** — on `Xiande-OS/Project`, *Settings →
   Actions → Allow all actions*. The synced `ci.yml` then runs there too, so CI
   results are visible publicly. Do **not** set `MIRROR_TOKEN` on the mirror —
   the `mirror` job is guarded to skip there (no loop, no secret needed).

3. **Test images (recommended)** — set `TEST_IMAGE_BASE_URL` (secret *or*
   variable) to a URL hosting faithful prebuilt images named
   `sdcard-<arch>-<libc>.img` (e.g. `sdcard-la-musl.img`). A GitHub Release on
   the mirror works well. CI downloads + caches these, so CI matches the grader
   exactly. **`la-musl` requires this** (see caveat below).

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
2. **`TEST_IMAGE_BASE_URL` set** → download `sdcard-<arch>-<libc>.img`
   (faithful; recommended).
3. **build from source** → clone upstream LTP `20240524`, cross-compile the
   subset, build a static busybox, assemble an ext2 image.

Toolchains for path 3: `rv-glibc`/`la-glibc` use the distro cross-gcc;
`rv-musl` pulls a musl cross from musl.cc.

### Caveat: `la-musl`

There is no packaged musl/LoongArch cross-toolchain, so `la-musl` **cannot
build from source** — it needs path 2 (`TEST_IMAGE_BASE_URL` with
`sdcard-la-musl.img`). Until that is provided, the `la-musl` cell fails with a
clear message. The other three cells build from source out of the box.

## Pass/fail gate (`ci/parse-ltp.sh`)

A cell fails on any of: a kernel panic/exception, init (pid 1) being killed, an
ltp group that started but never ended, or the rc==0 case count dropping below
`ci/baseline/<cell>.txt`.

**Baselines** are not committed yet. After the first green run, read each cell's
"cases rc==0" from its log and commit it as `ci/baseline/<cell>.txt` (e.g.
`echo 57 > ci/baseline/rv-glibc.txt`). The gate then catches regressions; bump a
baseline deliberately when a cell legitimately improves (CI prints a notice when
it does).
