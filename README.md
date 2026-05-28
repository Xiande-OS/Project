# xiande-OS

2026 全国大学生计算机系统能力大赛 操作系统设计赛 内核实现赛 参赛内核。

RISC-V (riscv64gc) 内核,Rust no_std + alloc,运行在 QEMU `virt` 上,
通过 OpenSBI 引导,带 virtio-blk / virtio-net、smoltcp、最小 EXT4 只读 +
内存覆盖、busybox-sh 加 fork+exec 跑测试集。

## 构建

构建依赖:`qemu-system-riscv64` 9.x、`rust-toolchain.toml` 钉的 nightly
工具链(`cargo` 首次调用会自动装)。第三方 crate 已 vendor 到 `vendor/`,
评测机不需要联网。

```sh
make all
```

会在仓库根目录产出两个 ELF:

- `kernel-rv` — RISC-V64 内核
- `kernel-la` — LoongArch64 占位(LA 端口尚未实现)

由于赛题评测机会过滤所有隐藏目录(包括 `.cargo`),`make all` 的第一步
`prepare` 会把 `cargo/` 拷成 `.cargo/`、`kernel/cargo/` 拷成
`kernel/.cargo/`,然后再调用 `cargo build --offline`。

## 运行

赛题评测命令:

```
qemu-system-riscv64 -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 \
    -bios default \
    -drive file=<sdcard>,if=none,format=raw,id=x0 \
    -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
    -no-reboot \
    -device virtio-net-device,netdev=net -netdev user,id=net \
    -rtc base=utc
```

启动后内核会:

1. mount EXT4 测试盘到 `/mnt`,枚举 `musl/` 与 `glibc/` 两个变体目录;
2. 对每个变体,按优先级遍历 `*_testcode.sh`(`basic` → `lua` → `busybox`
   → `libctest` → benchmarks);
3. 把脚本依次塞给 busybox-sh,每条用 `busybox timeout` 包住,防止单个
   测试卡死整套;
4. 测试脚本自己打印 `#### OS COMP TEST GROUP START/END xxx ####` 标记
   供评测机识别;
5. 跑完调用 SBI `system_reset` 关机。

## 源码结构

```
kernel/         内核源码
  src/arch/     RISC-V trap、上下文切换
  src/mm/       Sv39 页表、frame 分配、buddy 堆
  src/fs/       VFS,ext4/fat32/tmpfs/devfs/procfs/pipe/socket
  src/drivers/  virtio-blk、virtio-net
  src/net/      smoltcp 集成
  src/signal.rs POSIX 信号
  src/sync/     futex
  src/syscall/  约 130 个 syscall handler
  src/task/     任务、调度、CLONE_VM/THREAD/FS/FILES/SIGHAND/SETTLS、fork、execve
  src/contest_runner.rs 测试集 init 脚本生成器
  src/main.rs   kmain
vendor/         vendored 第三方 crate
xtask/          本地开发用工具(make all 不依赖它)
scripts/        辅助脚本(LA stub 生成等)
cargo/          .cargo/config.toml 的明名副本
kernel/cargo/   同上,kernel-local
```
