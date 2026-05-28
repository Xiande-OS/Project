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

Expected output (M0 acceptance):

```
xiande-os booting on hart 0
  dtb @ 0xbfe00000
M0: SBI console up. Halting.
```
