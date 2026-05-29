# xiande-OS

Contest kernel for the 2026 National College Student Computer System
Capability Competition — OS Design Track, Kernel Implementation.

A RISC-V (riscv64gc) kernel written in Rust (`no_std` + `alloc`), running on
QEMU `virt`, booted via OpenSBI. It has virtio-blk / virtio-net drivers, a
smoltcp network stack, a minimal read-only EXT4 with a tmpfs overlay, and runs
the contest test suite by exec'ing busybox-sh with full `fork`+`execve`.

## Build

Requirements: `qemu-system-riscv64` 9.x and the nightly toolchain pinned by
`rust-toolchain.toml` (the first `cargo` invocation installs it
automatically). All third-party crates are vendored under `vendor/`, so the
judge machine does not need network access.

```sh
make all
```

This produces two ELF files at the repository root:

- `kernel-rv` — the RISC-V64 kernel
- `kernel-la` — a LoongArch64 placeholder (the LA port is not yet implemented)

Because the judge strips every hidden directory (including `.cargo`), the
`prepare` step of `make all` first copies `cargo/` to `.cargo/` and
`kernel/cargo/` to `kernel/.cargo/`, then invokes `cargo build --offline`.

## Run

The judge boots the kernel with:

```
qemu-system-riscv64 -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 \
    -bios default \
    -drive file=<sdcard>,if=none,format=raw,id=x0 \
    -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
    -no-reboot \
    -device virtio-net-device,netdev=net -netdev user,id=net \
    -rtc base=utc
```

At boot the kernel:

1. mounts the EXT4 test disk at `/mnt` and enumerates the two variant
   directories `musl/` and `glibc/`;
2. for each variant, walks the `*_testcode.sh` scripts in priority order
   (`basic` → `lua` → `busybox` → `libctest` → benchmarks);
3. feeds each script to busybox-sh, wrapping each in `busybox timeout` so a
   single stuck test cannot hang the whole suite;
4. the test scripts themselves print the
   `#### OS COMP TEST GROUP START/END xxx ####` markers the judge matches on
   (the kernel never emits those markers itself);
5. when the suite finishes, calls SBI `system_reset` to power off.

The dynamic loaders the contest binaries reference under `/lib`
(`ld-linux-riscv64-lp64d.so.1`, `ld-musl-riscv64.so.1`, `libc.so`, ...) are
bound to the copies on the test disk at startup, as the contest rules require.

## Status

Measured on QEMU `virt` against a disk built from the official test-suite
Makefile (zero kernel panics; all 24 musl+glibc groups complete):

| Group        | musl        | glibc                          |
|--------------|-------------|--------------------------------|
| basic        | 32/32       | 32/32                          |
| lua          | 9/9         | 9/9                            |
| busybox      | 55/55       | 55/55                          |
| libctest     | **217/217** | 177/217                        |
| iperf        | 6/6         | 6/6                            |
| netperf      | 5/5         | 5/5                            |
| unixbench / libcbench / iozone | benchmark output | benchmark output |

The glibc libctest figure tracks the ceiling a real Linux kernel + real glibc
reaches on this (musl-authored) suite: the remaining cases are tests that
assert musl-specific behaviour or require glibc locale data, and fail on real
Linux glibc as well.

## Source layout

```
kernel/         kernel source
  src/arch/     RISC-V trap entry, context switch, timer preemption
  src/mm/       Sv39 page tables, frame allocator, buddy heap
  src/fs/       VFS: ext4 / fat32 / tmpfs / devfs / procfs / pipe / socket
  src/drivers/  virtio-blk, virtio-net
  src/net/      smoltcp integration + in-kernel 127.0.0.1 loopback
  src/signal.rs POSIX signal delivery + rt_sigframe
  src/vdso.rs   minimal vDSO (__vdso_rt_sigreturn with CFI for glibc unwind)
  src/sync/     futex
  src/syscall/  ~130 syscall handlers
  src/task/     tasks, scheduler, CLONE_VM/THREAD/FS/FILES/SIGHAND/SETTLS,
                fork, execve
  src/contest_runner.rs  test-suite init-script generator
  src/main.rs   kmain
vendor/         vendored third-party crates (offline build)
xtask/          local dev tooling (not used by `make all`)
scripts/        helper scripts (LA stub generation, etc.)
cargo/          plain-named copy of .cargo/config.toml
kernel/cargo/   same, kernel-local
```
