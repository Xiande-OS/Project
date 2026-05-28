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

Expected output (current — runs `git self-test` in U-mode):

```
xiande-os booting on hart 0
[user] loading git (3477512 bytes)
[user] argv = ["git", "self-test"]
hash-object empty string ... OK (e69de29bb2d1d6434b8b29ae775ad8c2e48c5391)
hash-object 'hello\n' ... OK (ce013625030ba8dba906f756967f9e9ca394464a)
hash-object 'xiande-os\n' ... OK (414df5b95b98ece65f5bc64478e689ee7cfc3b3f)
All self-tests passed.
[syscall] task exit(0)
```

Other commands (set `GIT_CMD` env var when building, or change the
default in `kernel/src/main.rs`):

| Command       | Output                                            |
|---------------|---------------------------------------------------|
| `--version`   | `git version 2.42.0-xiande-os ...`                |
| `log`         | Synthetic log of xiande-os milestones             |
| `status`      | `On branch main / nothing to commit`              |
| `init`        | `Initialized empty Git repository`                |
| `hash-object` | Real git blob SHA-1 over args/stdin               |
