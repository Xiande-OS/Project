# xiande-os

Research/experimental RISC-V (riscv64gc) operating-system kernel in Rust.
Long-term target: boot stock Linux user-space (musl static + dynamic, plus
`wget` over `smoltcp`) on QEMU `virt`. Current milestone: **M0 — SBI console**.

See [`.claude/GOALS.md`](.claude/GOALS.md) for the milestone roadmap,
[`.claude/DESIGN.md`](.claude/DESIGN.md) for architecture decisions, and
[`.claude/PROGRESS.md`](.claude/PROGRESS.md) for what's done / next.

## Build & run (M0)

Prereqs: `qemu-system-riscv64`, a nightly Rust toolchain. The pinned channel
in `rust-toolchain.toml` auto-installs on first `cargo` invocation.

```sh
cargo xtask qemu          # build kernel, boot under QEMU virt
cargo xtask build         # build only
cargo xtask qemu --gdb    # pause for gdb on :1234
cargo xtask qemu --smp 4  # M0 parks non-zero harts; real SMP is M2
```

Expected output (current — runs **upstream git 2.42.0** in U-mode):

```
xiande-os booting on hart 0
[user] loading real_git (2996872 bytes)
[user] argv = ["git", "--version"]
git version 2.42.0
[syscall] task exit(0)
```

The `git` binary is genuine upstream `git` 2.42.0, cross-compiled with
`riscv64-unknown-linux-musl-gcc 16.1.0` (from cross-tools/musl-cross)
against a self-built static zlib 1.3.1. Two tiny patches were needed
to work around C23 keyword collisions: rename `struct thread_local`
in `builtin/index-pack.c` and `unreachable(` in `reflog.c`.

`git --help` also runs in full, printing every common subcommand and
usage block. Commands that fork (e.g. `git config --list` paging
through `less`) fail at `pipe2`/`clone` — fork+exec lands in M5.

## Running the old fake-git self-test

The Rust toy `git` I wrote earlier still lives in `user/git/` for
reference; build with `--features rust_git`:

```
[user] loading git (3477512 bytes)
hash-object empty string ... OK (e69de29bb2d1d6434b8b29ae775ad8c2e48c5391)
hash-object 'hello\n' ... OK (ce013625030ba8dba906f756967f9e9ca394464a)
All self-tests passed.
```

Pass a different command via the `GIT_CMD` env var at kernel build
time (defaults to `--version` for `real_git`, `self-test` for `rust_git`).
