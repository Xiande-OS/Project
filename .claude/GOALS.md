# 目标（GOALS）

> 最近更新：2026-06-01（重写——立项时的"当前焦点 = M0 / 只对 M0 负责"已作废，M0–M8 全部达成）。

## 一句话总目标
用 Rust 在 RISC-V (`riscv64gc`) 上从零实现一个研究/实验型操作系统内核，在 QEMU `virt` 上跑普通的 Linux 用户态 ELF（静态 + 动态、musl + glibc）并通过 2026 OS 大赛测试套件；架构为 SMP 设计，当前单核 bring-up。另有 LoongArch64 端口。

## 当前实际目标（参赛得分）
评测机启动内核 + 一张 ext4 测试盘，内核遍历 `musl/`、`glibc/` 两变体的 `*_testcode.sh`，逐组打分。目标：**每组尽量多过、零 panic 跑完、最后干净关机**，让评测机检测到 QEMU 退出并累计分数。各组当前自测数字见 [PROGRESS.md](PROGRESS.md)。LTP 是分值大头（评测驱动跑两遍：精选白名单 + 全量扫尾）。

得分铁律（见 HANDOFF「工作纪律」）：**让测试转绿的每一处改动都必须是真实 OS 特性**——绝不按测例名特判、不塞假返回、不注入伪输出、不硬编码测试盘路径。

## 非目标（明确不做——仍然有效）
- 不追求 100% Linux 兼容（不实现 io_uring、cgroup 控制器、完整 namespaces、eBPF、KVM）。
- 不做产品级安全（KASLR/KPTI 等可后期）。
- 不做图形栈（无 framebuffer/GPU/wayland）。
- 不做嵌套虚拟化 / Hypervisor 扩展。
- 不支持非 QEMU `virt` 机型。
- **工具链不钉 nightly**：能用 stable 就用 stable，绝不钉具体日期的 nightly，不放 `rust-toolchain.toml`（评测机工具链升级路径会踩 EXDEV 等坑）。内核零 unstable feature。

## 里程碑（M0–M8，全部已达成，保留作历史）
- **M0** 项目骨架 + SBI 控制台 ✅
- **M1** trap / 内存 / 调度器骨架 ✅
- **M2** SMP 架构预留（当前单核 bring-up；锁/调度留了 hook）✅（架构层）
- **M3** 首个用户态进程 + syscall 框架 ✅
- **M4** musl 静态 hello（auxv/writev/...）✅
- **M5** BusyBox + fork/execve/wait4 + 信号 + VFS + pipe/dup/fcntl ✅
- **M6** 动态链接 + futex（PT_INTERP、mmap MAP_FIXED、mprotect、getrandom、uname）✅
- **M7** 块设备 + 持久 FS（virtio-blk + ext4 只读 / fat32）✅
- **M8** 网络栈 + socket（smoltcp + virtio-net，iperf/netperf）✅
- **M8+** 实际超出原路线图：glibc 兼容、vDSO、LTP 两遍调度、SysV IPC、splice 族、LoongArch64 端口、OOM/看门狗等健壮性。

> 原始路线图的"先把 M0 demo 跑起来、跑通停下汇报、不要现在写 SMP/网络/动态链接"等节奏约束**已全部作废**——那些功能现在都实现了。

## 协作约定（现行）
- 在指定分支开发并推送，不污染 main（见 HANDOFF）。
- 改完跑相关单点回归再合主线：改信号→pthread 系；改 fs→openat/fcntl 系；改网络→iperf/netperf；改 mm→fork-storm/libcbench。
- 全量只在关键修复合主线前、里程碑数字定型时跑（~12 分钟）。
- 每组测试配预算的目的不是等慢测试，而是"单组卡死不拖垮后面其他组"——预算 = 该组实际耗时 + 15–20% 余量，所有组之和 ≤ 评测机给 QEMU 的总时限。
