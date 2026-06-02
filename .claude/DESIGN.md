# 设计语言（DESIGN）

> 这个文件记录关键架构决策与设计语言（包括"为什么"）。任何重大改动后更新此文件并在 PROGRESS.md 记录日期。
> 最近更新：2026-06-01（现状校准：M0–M8 全部落地；记录几处被推翻的原始决策）

## 现状（2026-06-01）：设计已全部落地，有几处原始决策被推翻
本文件记录的是**立项时的架构意图**，大部分仍准确（Sv39、virtio-mmio、内存布局、锁层次、双架构…），但下面这些早期决策在实现中被推翻；正文相应处已就地更正，决策日志有对应条目：

| 原始决策 | 实际落地（已对照代码核实，2026-06-01） |
|---|---|
| 内核内部全 `async/await` + WaitQueue | **协作式调度 + trap 边界抢占 + per-syscall 看门狗**（0 个 `async fn`） |
| 仅 musl，不支持 glibc | **musl + glibc 双支持**（绑 glibc ld-linux/libc.so.6、按变体设 LD_LIBRARY_PATH） |
| sigreturn 用栈 trampoline | **改用 vDSO**（`__vdso_rt_sigreturn` 带 CFI 供 glibc unwind） |
| 持久 FS = FAT32(`fatfs`)/ext4(`lwext4-rs`) | **ext4 + fat32 全自实现**，无第三方 crate；ext4 只读为评测主路径 |
| buddy + slab(kmalloc) | 只有单个 buddy `LockedHeap`（256 MiB），**无 slab** |
| MemorySet 支持 demand paging + CoW | **两者均未实现**（mmap/fork 即时分配+深拷贝，缺页→信号） |
| 调度器 per-CPU FIFO runqueue + idle task | 全局 `BTreeMap` 任务表 + 扫表 round-robin，**无 per-CPU 队列/idle** |
| 时钟 10 ms tick | **1 ms**（10 MHz mtimer，`TIMER_QUANTUM_TICKS=10_000`） |
| PLIC + NS16550A IRQ | **均未用**：SBI legacy console + virtio 轮询 |
| initramfs（cpio newc） | **无 cpio**；rootfs 由 `kmain` `include_bytes!` 直接铺 tmpfs |
| crate 表含 hashbrown/cpio_reader/fatfs/lwext4-rs/crossbeam-queue | **均未使用**（见下方修正后的 crate 表） |
| 用户栈 `0x3f_ffff_f000` / interp `0x2aaa_…` | 实际栈顶 `0x4000_0000`、mmap base `0x2000_0000`（全在 1 GiB 下） |

文末「实施分期」表是 M0 时期的，**已作废**（全部已实现），仅留作历史。

## 整体形态
- **形态**：宏内核（monolithic），单地址空间内核（所有内核代码共享高半区映射）
- **执行模型**（⚠️ 与原计划不同，未采用 async）：单 hart **协作式调度 + trap 边界抢占**。syscall 同步执行；阻塞型 syscall 在内核里轮询/挂队列并在每次 trap 出口重新调度；`dispatch` 期间开 SIE，让嵌套 timer tick 驱动 **per-syscall 看门狗**（单条 syscall 在内核里 >8s 视为 wedge，按内核 fault 恢复路径丢弃该 case 让评测继续）。原计划的"全 `async fn` + `WaitQueue` + 自写 runtime"**未实现**（内核里 0 个 async fn）
- **语言契约**：内核 crate `#![no_std]`、`#![no_main]`；avoid panic in critical paths；用 newtype 包装物理/虚拟地址；锁的持有时间最小化

## 硬件 / 启动
- **目标三元组**：内核 = `riscv64gc-unknown-none-elf`；用户态 Rust = `riscv64gc-unknown-linux-musl`；用户态 C = `riscv64-linux-musl-gcc`（musl.cc 工具链）
- **机型**：QEMU `virt`，4 hart，1 GiB（默认），4 KiB 页，Sv39；M0–M1 阶段先用 1 hart，M2 起扩到 4 hart
- **固件**：OpenSBI `fw_jump.bin`（QEMU 内置即可），跳转到 `0x8020_0000` 的 S-mode 内核入口，`a0 = hartid`、`a1 = DTB 物理地址`
- **SBI 调用封装**：用 `sbi-rt` crate（HSM、IPI、timer、console、RFENCE 都齐全），不手写 ecall

## 内存
- **物理分配器**：`buddy_system_allocator` crate（页粒度）。内核 heap = 单个 `LockedHeap`（256 MiB 静态 `.bss`，包成 `PreemptHeap` 防持锁时被抢占）。⚠️ **未叠 slab/kmalloc**——一个 buddy heap 覆盖所有内核分配（`mm/heap.rs`）
- **虚拟内存**：**Sv39**（39 位 VA、3 级页表）。`PagingMode` trait 抽象层数与 VPN 位宽，未来切 Sv48 只改一处
- **内核地址空间**（高半区，符号扩展位 = 1）：
  ```
  0xffff_ffc0_0000_0000 .. 0xffff_ffd0_0000_0000  直接映射 (PHYS_OFFSET, 256GB, 1GB 大页)
  0xffff_ffd0_0000_0000 .. 0xffff_ffe0_0000_0000  vmalloc 区
  0xffff_ffe0_0000_0000 .. 0xffff_fff0_0000_0000  fixmap / per-cpu / IO 重映射
  0xffff_ffff_8000_0000 .. 0xffff_ffff_ffff_ffff  内核镜像 (-2GB，便于 mcmodel=medany)
  ```
- **用户地址空间**（⚠️ 实际布局，全在 1 GiB 以下，比原设计简单）：
  - 主程序 ELF 放在 `MMAP_BASE`(`0x2000_0000`) 下方的大空隙（`loader/mod.rs`）
  - `mmap` 区从 `MMAP_BASE = 0x2000_0000` 向上长
  - 用户栈顶 `USER_STACK_TOP = 0x4000_0000`，8 MiB，向下长
  - （原设计的 `0x2aaa_…` interp、`0x3f_ffff_f000` 栈未采用）
- **页表 Rust 抽象**：`PhysAddr`/`VirtAddr` newtype；`PageTable` 拥有根帧并在 Drop 时递归释放；用户进程的 `MemorySet`（类似 Linux VMA）。⚠️ **未实现 demand paging 与 CoW**：mmap 即时分配、fork 即时深拷贝（`alloc_uninit`+`copy_from_slice`，见 `memory_set.rs::fork`），用户缺页一律转成信号（无缺页重试、无写时复制）
- **CSR 操作**：用 `riscv` crate（v0.11+）的 register 模块

## 进程 / 线程 / 调度
- **task 结构**：`Task { tid, pid, tgid, mm: Arc<MemorySet>, files: Arc<FdTable>, sighand: Arc<SigHand>, state, kstack, trap_frame, ... }`
- **clone 语义**：精确解析 flags；fork = 复制 mm + fd 表 + sighand；pthread_create = 全共享 + 新 tid + 设 tp + 写 child_tid
- **调度器**（⚠️ 实际）：单 hart，全局 `TaskTable { tasks: BTreeMap<i32, Arc<Task>> }`，`pick_ready` 扫表选下一个 Ready，trap 边界 round-robin。**无 per-CPU runqueue、无专门 idle task**（无可运行任务时自旋扫醒睡眠/futex/网络队列）
- **时钟**（⚠️ 实际）：SBI `set_timer`，**1 ms** 抢占片（10 MHz mtimer，`TIMER_QUANTUM_TICKS=10_000`），非 10 ms

## SMP 与同步
- **per-CPU 数据**：`tp` 寄存器持有当前 hart 的 `CpuLocal` 结构体指针。**手工 offset 访问**，不依赖 `#[thread_local]`
- **锁**（⚠️ 实际只有一种）：`sync::Mutex<T>`（包 `spin::Mutex`）。它**不关中断**，只 bump 一个 per-hart `preempt_disable` 软件计数；调度器在计数非 0 时拒绝切换（单 hart 上抢占持锁者会让下一个任务在锁上空转）。**关键副作用**：持锁时 timer 照常打、`watchdog_overrun()` 全 lock-free，所以持锁的内核 wedge 仍能被 per-syscall 看门狗观测到。原计划的"禁 sie 的 `SpinLock` + 可睡眠 `Mutex` + `WaitQueue`"未实现
- **锁顺序约定**：mm_lock → vma_lock → page_table_lock；vfs_lock → inode_lock → page_cache_lock；fd_table_lock 独立
- **多 hart 启动**：boot hart 做完早期初始化后通过 SBI `HSM hart_start` 唤醒其他 hart；其他 hart 从 `_secondary_start` 进入；全局 `AtomicUsize cpus_online` 同步
- **TLB shootdown**：用 SBI `remote_sfence_vma(hart_mask, start, size)`，**不自己手搓 IPI shootdown**
- **内存序**：RISC-V RVWMO，Rust 的 `AtomicXxx::Ordering` 即足；MMIO 前后用 `fence io,io`；改页表后必须 `sfence.vma`

> **M0–M1 落地说明**：单 hart bring-up，per-CPU 抽象先按"hart 0 only"的退化实现，但 trait 与 `SpinLock` 的 IRQ-aware 接口要先建好；M2 时只补 secondary hart 的启动与 RFENCE 调用，不重写 API。

## 异常与中断
- **trap.S 模式**：`stvec` Direct 模式单入口，scause 高位分流中断/异常；用 `sscratch` 实现用户/内核栈切换
- **保存范围**：汇编保存全部 31 个通用寄存器到 `TrapFrame`；FP 与 V 寄存器 lazy save（第一次 FP/V 异常时再处理）
- **PLIC**：⚠️ **未实现**。riscv64 不走外部中断——控制台用 SBI console，virtio 用**轮询**（trap 出口 `net::poll`、块设备同步读写），trap 只处理 SupervisorTimer + 异常，其它中断打印后屏蔽

## 设备驱动
- **virtio**：用 `virtio-drivers` crate（rcore-os 维护，成熟），自己只实现 `Hal` trait（dma_alloc / phys_to_virt）
- **总线**：只走 **virtio-mmio**（扫 0x10001000 起），不走 PCI
- **UART**（⚠️ 实际）：riscv64 **全程用 SBI legacy console**（`console_putchar/getchar`，`arch/riscv64/console.rs`），未切到 NS16550A + IRQ。（loongarch64 端直接 MMIO 16550）
- **virtio-blk**：modern 接口；包到 `BlockDevice` trait 给自实现的 ext4/fat32 用
- **virtio-net**：给 `smoltcp` 实现 `phy::Device`；buffer 池 `[u8; 1536]`
- **目录树解析**：用 `fdt` crate 解析 DTB

## VFS 与文件系统
- **三层抽象**：`Inode` / `Dentry` / `File`，主路径用 `Arc<dyn Inode>` trait object
- **fd 表**：进程持有 `FdTable { table: Vec<Option<Arc<FileDescriptor>>>, cloexec_bitmap: BitVec }`；`Arc` 让 dup/fork 共享 file description
- **内置 FS**：
  - **tmpfs**（自实现）：Inode 持有 `RwLock<Vec<u8>>` 或页帧列表
  - **devfs**（自实现）：硬编码 `null/zero/full/random/urandom/tty/console`
  - **procfs**（自实现）：动态生成，**必须支持** `/proc/self/exe`（musl ld.so 用它做 origin 解析）、`/proc/self/maps`、`/proc/self/cmdline`、`/proc/mounts`、`/proc/cpuinfo`
- **持久 FS**（⚠️ 实际全自实现，无第三方 crate）：**ext4 只读**（`fs/ext4.rs`，评测盘主路径）+ **fat32**（`fs/fat32.rs`，本地 dev 盘）。**没用 `fatfs`/`lwext4-rs`**
- **rootfs 构建**（⚠️ 实际，非 cpio）：`kmain` 把 `include_bytes!` 进内核的 busybox/git/loader 等直接装进 tmpfs，并铺 `/bin` `/lib` `/etc` `/dev` `/sys`。**没有 cpio/initramfs**

## Linux ABI（riscv64）
- **syscall 编号**：直接采用 Linux `include/uapi/asm-generic/unistd.h` 的 generic riscv64 表
- **errno**：直接采用 Linux asm-generic errno（EPERM=1 .. ENOSYS=38 ...）
- **libc 目标**（⚠️ 已扩展为 musl + glibc）：musl 先打通（单文件 ld、依赖 syscall 少、不依赖 `clone3/membarrier/rseq/io_uring`）；glibc 后续补齐——它把内核当真 Linux 用，挑剔 ABI 精确度（uc_mcontext 偏移、st_rdev、vDSO+CFI、futex 绝对超时…），逐一啃通。`contest_runner` 绑 glibc 的 `ld-linux-riscv64-lp64d.so.1` / `libc.so.6` / `libm.so.6` 并按变体设 `LD_LIBRARY_PATH`
- **ELF 加载**：
  - 静态：映射所有 PT_LOAD，跳到 `e_entry`
  - 动态：解析 PT_INTERP → 加载 ld.so 到高地址 → 入口 = ld.so 的 `e_entry`，主程序信息通过 auxv 传给 ld.so
- **初始栈布局**（musl 强依赖）：从高到低 = [字符串区] [auxv] [envp + NULL] [argv + NULL] [argc]，sp 16 字节对齐
- **必填 auxv**：AT_PHDR/PHENT/PHNUM/PAGESZ/BASE/ENTRY/RANDOM/UID/EUID/GID/EGID/HWCAP/PLATFORM/SECURE/EXECFN——**AT_RANDOM 必须可读 16 字节**，缺它 musl 早期 crash
- **信号 sigreturn**（⚠️ 已切到 vDSO）：内核映射一个极小 vDSO（`vdso.rs` + `vdso/rt_sigreturn.S`），`__vdso_rt_sigreturn` 的 `.eh_frame` 带 `.cfi_signal_frame` CFI——glibc/libgcc 的 unwinder 需要它才能正确回溯信号帧。早期"在栈上写 `li a7,139; ecall`"的 trampoline 方案已弃用

## 网络
- **栈**：`smoltcp` 0.11+，作为单例 `NetStack { iface, sockets }`，spin Mutex 保护
- **socket 层**：自实现 `KSocket: File` 把 Linux socket syscall 翻译到 smoltcp，使其纳入 fd 表
- **驱动循环**（⚠️ 实际）：在 trap 出口轮询 `iface.poll`（`schedule_next_after_trap` 调 `net::poll_with_progress`），**无独立 poll 任务、无网卡 IRQ**
- **DNS**（⚠️ 实际）：`/etc/resolv.conf` 写 `nameserver 127.0.0.1`；smoltcp 启用 `socket-dns` feature + 内核内 127.0.0.1 loopback。非原设计的"用户态解析、指向 10.0.2.3"
- **QEMU 网络**：`-netdev user,id=net0 -device virtio-net-device,netdev=net0` 即可出网

## 关键 crate 依赖（⚠️ 实际，以 `kernel/Cargo.toml` 为准）
| 用途 | crate |
|---|---|
| SBI 调用（riscv64） | `sbi-rt`（legacy） |
| CSR 操作（riscv64） | `riscv` 0.11 |
| 帧分配 + 内核 heap | `buddy_system_allocator` 0.10（`LockedFrameAllocator` + `LockedHeap`） |
| 自旋锁/RwLock | `spin` 0.9 |
| bitflags | `bitflags` 2.6 |
| DTB 解析 | `fdt` 0.1 |
| ELF 解析 | `xmas-elf` 0.9 |
| virtio 驱动 | `virtio-drivers` 0.7 |
| 网络栈 | `smoltcp` 0.11 |
| 日志 | `log` 0.4 |

**自实现 / 未用 crate**：HashMap 改用 `alloc::collections::BTreeMap`、**ext4**（`fs/ext4.rs`）、**fat32**（`fs/fat32.rs`）、tmpfs/devfs/procfs、pipe/socket、信号、futex 均自实现。原设计列的 `hashbrown` / `cpio_reader` / `fatfs` / `lwext4-rs` / `crossbeam-queue` **均未使用**。（帧分配仍用 `buddy_system_allocator::LockedFrameAllocator`，非自实现。）

## 已有项目参考（不复制，只学）
| 项目 | 借鉴 | 不借鉴 |
|---|---|---|
| rCore-Tutorial v3 | 目录结构、trap.S 模板、SBI 用法 | 单核假设、锁粒度粗 |
| Asterinas | `Frame`/`MemorySet` 类型化、async 框架思想 | 重 framework、能力模型 |
| Phoenix (赛题) | syscall 兼容覆盖、ELF/auxv 构造、async I/O | 比赛特化路径 |
| Titanix | sigreturn 栈 trampoline 实现 | — |
| Starry / Starry-Next (ArceOS 家族) | clone/execve 干净实现、组件化 | 单地址空间宏架构选择 |
| Maestro | Linux ABI 兼容广度 | — |

## 仓库目录骨架（⚠️ M0 时的规划，已演进——实际目录见 HANDOFF「代码地图」；下树仅存历史，含未采用的 `rust-toolchain.toml`/`sched/`/`uart_16550.rs`/`plic.rs` 等）
```
xiande-os/
├── Cargo.toml            # workspace
├── rust-toolchain.toml   # nightly + riscv64gc-unknown-none-elf
├── kernel/
│   ├── Cargo.toml
│   ├── linker.ld
│   ├── .cargo/config.toml
│   └── src/
│       ├── main.rs
│       ├── arch/riscv64/{boot.S, trap.S, mod.rs, ...}
│       ├── mm/{frame.rs, memory_set.rs, page_table.rs, ...}
│       ├── sync/{spinlock.rs, waitqueue.rs, futex.rs}
│       ├── sched/{mod.rs, task.rs, scheduler.rs}
│       ├── fs/{vfs/, tmpfs.rs, devfs.rs, procfs.rs, initramfs.rs, ...}
│       ├── drivers/{virtio/, uart_16550.rs, plic.rs}
│       ├── net/{socket.rs, stack.rs}
│       ├── syscall/{mod.rs, nr.rs, fs.rs, mm.rs, process.rs, signal.rs, net.rs}
│       ├── signal/mod.rs
│       └── loader/elf.rs
├── user/                 # 测试用户态程序与 BusyBox/musl 制作脚本
├── xtask/                # 自定义 cargo 子命令：qemu、image、rootfs、check
└── .claude/              # 同步给协作 agent 的状态
    ├── PROGRESS.md
    ├── GOALS.md
    ├── DESIGN.md
    └── HANDOFF.md
```

## 实施分期（架构 vs. 代码落地）— ⚠️ 已作废（2026-06-01）
> 下表是 M0 时期"先实现哪些"的规划。**现在所有模块均已实现**，保留作历史，勿据此判断现状（看 PROGRESS.md）。

| 设计模块 | 当前阶段 (M0) 是否要写代码 | 备注 |
|---|---|---|
| boot.S 单 hart 入口 | ✅ 必须 | M0 验收的核心 |
| SBI 控制台输出 | ✅ 必须 | M0 验收的核心 |
| linker.ld + cargo target | ✅ 必须 | M0 验收的核心 |
| trap / 内存 / 调度 | ⛔ M1 才做 | M0 阶段把目录占位即可 |
| SMP / per-CPU | ⛔ M2 才做 | M0–M1 给 IRQ-aware 锁与 per-CPU 接口留好 trait，但不实现 secondary |
| 用户态 / syscall | ⛔ M3+ | 留模块占位 |
| VFS / FS | ⛔ M5+ | 留模块占位 |
| ELF 动态链接 | ⛔ M6 | 静态加载先于 M3，动态 M6 |
| 块设备 / FAT32 | ⛔ M7 | 留 trait |
| 网络栈 / socket | ⛔ M8 | 留 trait 与 `net/` 目录 |

**（历史原则）M0 只写 M0 需要的代码，其余是未来 milestone 的 contract——此约束已随 M0–M8 完成而作废。**

## 决策日志（增量追加，每条配日期）
- 2026-05-28（立项）：确定 Sv39 起步、SMP 架构层支持但单核 bring-up、musl-only、initramfs 走 cpio、virtio-mmio 用 `virtio-drivers` crate、smoltcp 作为唯一网络栈、sigreturn 用栈 trampoline 而非 vDSO
- 2026-05-28（pivot 提议）：曾短暂收窄到"单核 + 静态 git"，并把 SMP / 网络 / 动态链接 / async 移到"已撤销"段
- 2026-05-28（第三轮校准）：**撤回 pivot**。架构设计恢复到立项原状（保留 SMP/网络/动态链接/async 全栈设计），但实施节奏改为"**只做 M0**，跑通后停下来汇报"。原因：用户希望先把基本 demo 跑起来，但不希望在设计层就把后续能力封死——"留接口，demo 先不要"
- 2026-06-01（现状校准）：M0–M8 全部落地后，记录几处**被推翻的原始决策**（正文已就地更正）：
  - **async → 协作式 + 抢占 + 看门狗**：全 async/WaitQueue 未采用；改为同步 syscall + trap 边界抢占调度，dispatch 期间开 SIE 让 per-syscall 看门狗（>8s）兜住内核内 wedge。原因：协作式更易推理 lost-wakeup（见 commit `2db1b76` "defer mid-syscall preemption"），async 收益不抵复杂度。
  - **musl-only → musl + glibc**：评测盘有 glibc 变体，glibc 的 ABI 精确度要求（uc_mcontext、st_rdev、vDSO+CFI、futex 绝对超时）逐一补齐。
  - **栈 trampoline → vDSO**：glibc/libgcc unwinder 需要 `.cfi_signal_frame`，故映射带 CFI 的 vDSO（`vdso.rs`）。
  - **FAT32 起步 → ext4 只读为评测主路径**（fat32 仅本地 dev 盘）。
  - 工具链：**不钉 nightly、不放 `rust-toolchain.toml`**（rustup 升级在评测机跨挂载点 rename 报 EXDEV）；内核零 unstable feature，stable 即可构建。
- 2026-06-01（二次核对，对照代码逐条）：补记其余设计↔实现差异（正文已就地更正，索引见顶部「现状」表）——heap 无 slab；无 demand paging / CoW；调度用全局 `BTreeMap` 任务表而非 per-CPU runqueue，无 idle task；抢占片 1 ms 非 10 ms；PLIC / NS16550A 均未用（SBI console + virtio 轮询）；无 cpio initramfs（`kmain` 直接铺 tmpfs）；ext4 / fat32 自实现（未用 `fatfs` / `lwext4-rs`）；crate 表删去 `hashbrown` / `cpio_reader` / `crossbeam-queue` 等未用项；用户地址布局实际全在 1 GiB 以下；锁只有一种 preempt-safe `Mutex`（不关中断、无 sie 操作、无 WaitQueue），其"timer 照常打"是看门狗能兜住持锁 wedge 的前提。
