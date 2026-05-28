# 设计语言（DESIGN）

> 这个文件记录关键架构决策与设计语言（包括"为什么"）。任何重大改动后更新此文件并在 PROGRESS.md 记录日期。
> 最近更新：2026-05-28（第三轮校准：保留全栈设计，但当前实施只到 M0）

## 整体形态
- **形态**：宏内核（monolithic），单地址空间内核（所有内核代码共享高半区映射）
- **执行模型**：内核内部用 **Rust async/await**，所有可阻塞 syscall（read/write/poll/futex/socket）实现为 `async fn`。每个 hart 跑一个简单的轮询执行器，所有阻塞点统一为 `WaitQueue`（push waker / 条件唤醒）。**不引入 embassy**，自己写极小 runtime
- **语言契约**：内核 crate `#![no_std]`、`#![no_main]`；avoid panic in critical paths；用 newtype 包装物理/虚拟地址；锁的持有时间最小化

## 硬件 / 启动
- **目标三元组**：内核 = `riscv64gc-unknown-none-elf`；用户态 Rust = `riscv64gc-unknown-linux-musl`；用户态 C = `riscv64-linux-musl-gcc`（musl.cc 工具链）
- **机型**：QEMU `virt`，4 hart，1 GiB（默认），4 KiB 页，Sv39；M0–M1 阶段先用 1 hart，M2 起扩到 4 hart
- **固件**：OpenSBI `fw_jump.bin`（QEMU 内置即可），跳转到 `0x8020_0000` 的 S-mode 内核入口，`a0 = hartid`、`a1 = DTB 物理地址`
- **SBI 调用封装**：用 `sbi-rt` crate（HSM、IPI、timer、console、RFENCE 都齐全），不手写 ecall

## 内存
- **物理分配器**：`buddy_system_allocator` crate 起步（页粒度 buddy），上面再叠一个 slab 分配小对象（kmalloc）
- **虚拟内存**：**Sv39**（39 位 VA、3 级页表）。`PagingMode` trait 抽象层数与 VPN 位宽，未来切 Sv48 只改一处
- **内核地址空间**（高半区，符号扩展位 = 1）：
  ```
  0xffff_ffc0_0000_0000 .. 0xffff_ffd0_0000_0000  直接映射 (PHYS_OFFSET, 256GB, 1GB 大页)
  0xffff_ffd0_0000_0000 .. 0xffff_ffe0_0000_0000  vmalloc 区
  0xffff_ffe0_0000_0000 .. 0xffff_fff0_0000_0000  fixmap / per-cpu / IO 重映射
  0xffff_ffff_8000_0000 .. 0xffff_ffff_ffff_ffff  内核镜像 (-2GB，便于 mcmodel=medany)
  ```
- **用户地址空间**（低半区）：
  - `0x10000` 起放主程序 ELF；`mmap_min_addr = 0x10000` 阻止 NULL deref
  - PT_INTERP 装到 `~0x2aaa_aaaa_0000`
  - `mmap` 区从 `TASK_SIZE/3` 向上长；stack 从 `0x0000_003f_ffff_f000` 向下长
- **页表 Rust 抽象**：`PhysAddr`/`VirtAddr` newtype；`PageTable` 拥有根帧并在 Drop 时递归释放；用户进程的 `MemorySet { page_table, areas: BTreeMap<VirtAddr, VmArea> }`（类似 Linux VMA），支持 demand paging、CoW（后期）
- **CSR 操作**：用 `riscv` crate（v0.11+）的 register 模块

## 进程 / 线程 / 调度
- **task 结构**：`Task { tid, pid, tgid, mm: Arc<MemorySet>, files: Arc<FdTable>, sighand: Arc<SigHand>, state, kstack, trap_frame, ... }`
- **clone 语义**：精确解析 flags；fork = 复制 mm + fd 表 + sighand；pthread_create = 全共享 + 新 tid + 设 tp + 写 child_tid
- **调度器**：起步用 per-CPU FIFO runqueue + idle task；公平性放到后期（CFS 太复杂，先用 round-robin）
- **时钟**：SBI timer，10 ms tick 起步

## SMP 与同步
- **per-CPU 数据**：`tp` 寄存器持有当前 hart 的 `CpuLocal` 结构体指针。**手工 offset 访问**，不依赖 `#[thread_local]`
- **锁层次**：
  - `RawSpinLock`：atomic CAS，不动中断（极少用）
  - `SpinLock<T>`：进入时保存并禁本地 sie，释放时恢复——内核大部分场景用这个
  - `Mutex<T>`：可睡眠锁，给 async 上下文用，底层挂 WaitQueue
- **锁顺序约定**：mm_lock → vma_lock → page_table_lock；vfs_lock → inode_lock → page_cache_lock；fd_table_lock 独立
- **多 hart 启动**：boot hart 做完早期初始化后通过 SBI `HSM hart_start` 唤醒其他 hart；其他 hart 从 `_secondary_start` 进入；全局 `AtomicUsize cpus_online` 同步
- **TLB shootdown**：用 SBI `remote_sfence_vma(hart_mask, start, size)`，**不自己手搓 IPI shootdown**
- **内存序**：RISC-V RVWMO，Rust 的 `AtomicXxx::Ordering` 即足；MMIO 前后用 `fence io,io`；改页表后必须 `sfence.vma`

> **M0–M1 落地说明**：单 hart bring-up，per-CPU 抽象先按"hart 0 only"的退化实现，但 trait 与 `SpinLock` 的 IRQ-aware 接口要先建好；M2 时只补 secondary hart 的启动与 RFENCE 调用，不重写 API。

## 异常与中断
- **trap.S 模式**：`stvec` Direct 模式单入口，scause 高位分流中断/异常；用 `sscratch` 实现用户/内核栈切换
- **保存范围**：汇编保存全部 31 个通用寄存器到 `TrapFrame`；FP 与 V 寄存器 lazy save（第一次 FP/V 异常时再处理）
- **PLIC**：MMIO 0x0c00_0000；S-mode hart 0 的 context 是 1；标准 claim → dispatch → complete 流程

## 设备驱动
- **virtio**：用 `virtio-drivers` crate（rcore-os 维护，成熟），自己只实现 `Hal` trait（dma_alloc / phys_to_virt）
- **总线**：只走 **virtio-mmio**（扫 0x10001000 起），不走 PCI
- **UART**：QEMU virt 是 **NS16550A** @ 0x1000_0000；早期 boot 用 SBI console，驱动起来后切到 16550 + IRQ
- **virtio-blk**：modern 接口；包到 `BlockDevice` trait 给 fatfs/ext4 用
- **virtio-net**：给 `smoltcp` 实现 `phy::Device`；buffer 池 `[u8; 1536]`
- **目录树解析**：用 `fdt` crate 解析 DTB

## VFS 与文件系统
- **三层抽象**：`Inode` / `Dentry` / `File`，主路径用 `Arc<dyn Inode>` trait object
- **fd 表**：进程持有 `FdTable { table: Vec<Option<Arc<FileDescriptor>>>, cloexec_bitmap: BitVec }`；`Arc` 让 dup/fork 共享 file description
- **内置 FS**：
  - **tmpfs**（自实现）：Inode 持有 `RwLock<Vec<u8>>` 或页帧列表
  - **devfs**（自实现）：硬编码 `null/zero/full/random/urandom/tty/console`
  - **procfs**（自实现）：动态生成，**必须支持** `/proc/self/exe`（musl ld.so 用它做 origin 解析）、`/proc/self/maps`、`/proc/self/cmdline`、`/proc/mounts`、`/proc/cpuinfo`
- **持久 FS**：起步 **FAT32**（`fatfs` crate 读写稳）；后期可加 ext4 只读（`lwext4-rs`）
- **initramfs**：cpio newc，启动早期解压到 tmpfs。**最早期 rootfs 路径**，避开块设备依赖

## Linux ABI（riscv64）
- **syscall 编号**：直接采用 Linux `include/uapi/asm-generic/unistd.h` 的 generic riscv64 表
- **errno**：直接采用 Linux asm-generic errno（EPERM=1 .. ENOSYS=38 ...）
- **libc 目标**：**仅 musl**（不支持 glibc）；理由：musl 单文件 ld、依赖 syscall 少（不依赖 `clone3/membarrier/rseq/io_uring`）、容易准备 sysroot
- **ELF 加载**：
  - 静态：映射所有 PT_LOAD，跳到 `e_entry`
  - 动态：解析 PT_INTERP → 加载 ld.so 到高地址 → 入口 = ld.so 的 `e_entry`，主程序信息通过 auxv 传给 ld.so
- **初始栈布局**（musl 强依赖）：从高到低 = [字符串区] [auxv] [envp + NULL] [argv + NULL] [argc]，sp 16 字节对齐
- **必填 auxv**：AT_PHDR/PHENT/PHNUM/PAGESZ/BASE/ENTRY/RANDOM/UID/EUID/GID/EGID/HWCAP/PLATFORM/SECURE/EXECFN——**AT_RANDOM 必须可读 16 字节**，缺它 musl 早期 crash
- **信号 sigreturn trampoline**：栈方案（在 sigframe 后写 `li a7,139; ecall`，要求栈页可执行），不做 vDSO。后期再切 vDSO

## 网络
- **栈**：`smoltcp` 0.11+，作为单例 `NetStack { iface, sockets }`，spin Mutex 保护
- **socket 层**：自实现 `KSocket: File` 把 Linux socket syscall 翻译到 smoltcp，使其纳入 fd 表
- **驱动循环**：单独内核任务 `iface.poll(now, &mut device, &mut sockets)` + 网卡 IRQ 触发的 poll
- **DNS**：用户态做，不在内核解析；`/etc/resolv.conf` 指向 10.0.2.3（QEMU user-net 内置）
- **QEMU 网络**：`-netdev user,id=net0 -device virtio-net-device,netdev=net0` 即可出网

## 关键 crate 依赖（确定）
| 用途 | crate |
|---|---|
| SBI 调用 | `sbi-rt` |
| CSR 操作 | `riscv` (0.11+) |
| 物理分配器 | `buddy_system_allocator` |
| 自旋锁/RwLock 起步 | `spin` |
| 无 std HashMap | `hashbrown` |
| bitflags | `bitflags` |
| DTB 解析 | `fdt` |
| ELF 解析 | `xmas-elf` |
| cpio (initramfs) | `cpio_reader` |
| virtio 驱动 | `virtio-drivers` |
| FAT32 | `fatfs` |
| ext4 (后期可选) | `lwext4-rs` |
| 网络栈 | `smoltcp` |
| 无锁队列 | `crossbeam-queue` |

## 已有项目参考（不复制，只学）
| 项目 | 借鉴 | 不借鉴 |
|---|---|---|
| rCore-Tutorial v3 | 目录结构、trap.S 模板、SBI 用法 | 单核假设、锁粒度粗 |
| Asterinas | `Frame`/`MemorySet` 类型化、async 框架思想 | 重 framework、能力模型 |
| Phoenix (赛题) | syscall 兼容覆盖、ELF/auxv 构造、async I/O | 比赛特化路径 |
| Titanix | sigreturn 栈 trampoline 实现 | — |
| Starry / Starry-Next (ArceOS 家族) | clone/execve 干净实现、组件化 | 单地址空间宏架构选择 |
| Maestro | Linux ABI 兼容广度 | — |

## 仓库目录骨架（M0 时建立）
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

## 实施分期（架构 vs. 代码落地）
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

**原则：M0 只写 M0 需要的代码。设计文档里其他部分是给未来 milestone 的 contract，不要现在就实现。**

## 决策日志（增量追加，每条配日期）
- 2026-05-28（立项）：确定 Sv39 起步、SMP 架构层支持但单核 bring-up、musl-only、initramfs 走 cpio、virtio-mmio 用 `virtio-drivers` crate、smoltcp 作为唯一网络栈、sigreturn 用栈 trampoline 而非 vDSO
- 2026-05-28（pivot 提议）：曾短暂收窄到"单核 + 静态 git"，并把 SMP / 网络 / 动态链接 / async 移到"已撤销"段
- 2026-05-28（第三轮校准，本次）：**撤回 pivot**。架构设计恢复到立项原状（保留 SMP/网络/动态链接/async 全栈设计），但实施节奏改为"**只做 M0**，跑通后停下来汇报"。原因：用户希望先把基本 demo 跑起来，但不希望在设计层就把后续能力封死——"留接口，demo 先不要"
