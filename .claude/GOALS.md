# 目标（GOALS）

> 2026-05-28 第三轮校准：架构上**保留**网络栈、ELF 加载（静态+动态）、SMP 等扩展接口；实现上**先把 M0 demo 跑起来**，后续 milestone 按情况推进，不强行追终极验收。

## 一句话总目标
用 Rust 在 RISC-V (riscv64gc) 上从零实现一个研究/实验型操作系统内核，最终能在 QEMU `virt` 机型上**运行普通的 riscv64 Linux 用户态 ELF 程序**，覆盖**动态链接 (musl)** 与**网络程序 (如 wget)**，从一开始架构就为 SMP 设计（初期单核 bring-up）。

## 当前实施焦点
**M0 demo 优先**——先把内核启动到能打印第一行字符串。后面各 milestone 的"完整实现"是远期路线图，不是当前必须达成；架构层面给它们留好接口即可。

## 非目标（明确不做）
- 不追求 100% Linux 兼容（不实现 io_uring、cgroup、namespaces、eBPF、KVM 等）
- 不支持 glibc 二进制（仅 musl）
- 不做产品级安全（KASLR、KPTI、CFI 可后期再说）
- 不做图形栈（无 framebuffer / GPU / wayland）
- 不做嵌套虚拟化、Hypervisor extension
- 不支持非 QEMU virt 机型（HiFive、licheepi 等可后期再说）

## 成功验收（最终远期）
在 QEMU virt（4 个 hart，1 GiB 内存，virtio-mmio）上完成以下一连串测试：
1. 静态链接 `hello.c`（musl 编译）能打印 "hello" 并正确退出
2. BusyBox shell 能跑 `ls / cat / echo / pipe / wait`
3. 动态链接的二进制（依赖 `ld-musl-riscv64.so.1`）能跑
4. `wget http://10.0.2.2/index.html`（QEMU user-net）能成功下载

> 注：这是远期总验收。**当前只追到 M0 一个一个往后走**，不强求一次性把这四条都做出来。

## Milestone 列表与验收

### M0 — 项目骨架与 SBI 控制台 ★ **当前焦点**
- **产出**：Cargo workspace、`riscv64gc-unknown-none-elf` 交叉编译、QEMU 启动脚本、boot.S 单 hart 入口
- **验收**：`xtask qemu` 能在 QEMU virt 上打印 "xiande-os booting on hart 0"

### M1 — trap / 内存 / 调度器骨架（单 hart）
- **产出**：trap.S 框架 + scause 分发、buddy 物理页分配器、Sv39 页表抽象、高半区跳转、时钟中断、最小调度器（idle + 内核线程）
- **验收**：两个内核线程交替打印；除零异常被捕获并 panic 信息正确

### M2 — SMP 上线
- **产出**：HSM 唤醒次级 hart、per-CPU 数据（tp 寄存器 + 手工 offset）、IRQ-aware spinlock、TLB shootdown via SBI RFENCE
- **验收**：4 个 hart 同时跑同一组内核线程，调度均衡；并发原子计数器测试通过
- *注：M0–M1 阶段不需要写 SMP 实现代码，但锁/调度的抽象要给 SMP 留 hook（per-CPU 接口、IRQ-aware 锁 trait）*

### M3 — 首个用户态进程与 syscall 框架
- **产出**：ELF 加载器（仅 PT_LOAD）、用户页表与切换、syscall 分发表骨架、`write`/`exit`/`brk`/`mmap` 实现
- **验收**：手写汇编的 user-mode 程序通过 `ecall` 打印并退出

### M4 — musl 静态 hello（约 15 个 syscall）
- **产出**：完整初始栈与 auxv（含 AT_RANDOM）、`writev`、`set_tid_address`、`set_robust_list`、`ioctl`(TCGETS 桩)、uid/gid 桩等
- **验收**：`riscv64-linux-musl-gcc -static hello.c` 产物正常输出且 `exit_group(0)`

### M5 — BusyBox shell + 基本命令
- **产出**：`fork`/`execve`/`wait4`、`rt_sigaction` + 栈 sigreturn trampoline、初步 VFS（Inode/Dentry/File 三层）、initramfs (cpio)、tmpfs/devfs/procfs、fd 表、`pipe2`/`dup3`/`getdents64`/`fcntl`
- **验收**：BusyBox `ash` 交互式运行 `ls /`、`cat /etc/foo`、`echo a | grep a`

### M6 — 动态链接 + futex
- **产出**：`PT_INTERP` 加载 `ld-musl-riscv64.so.1`、auxv 完整正确（AT_BASE/AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY）、`mmap MAP_FIXED` 真实覆盖、`mprotect`、`futex` (WAIT/WAKE/PRIVATE)、`getrandom`、`uname`、`/proc/self/exe`
- **验收**：动态链接的 `hello`、`busybox --install` 后的多 applet 跑通

### M7 — 块设备与持久文件系统
- **产出**：DTB 解析 (`fdt` crate)、virtio-mmio 扫描、virtio-blk 驱动（用 `virtio-drivers` crate）、FAT32 读写（`fatfs` crate）或 ext4 只读
- **验收**：`mount /dev/vda /mnt` 后 `ls /mnt` 与 `cat /mnt/test.txt` 正确；写也要通

### M8 — 网络栈 + wget
- **产出**：virtio-net + `smoltcp` 0.11+ 集成、socket syscall（`socket`/`bind`/`connect`/`accept4`/`send*`/`recv*`/`shutdown`/`getsockopt`/`setsockopt`）、`ppoll`、用户态 DNS（/etc/resolv.conf → 10.0.2.3 UDP 53）
- **验收**：`wget http://10.0.2.2/index.html` 成功

## 时间预期（粗估，研究项目 solo 节奏）
- M0–M1：2–3 周
- M2：1–2 周（先跳过实现，留 hook 即可，等 M5 后回来做）
- M3–M4：3–4 周
- M5：2–3 周
- M6：1–2 周
- M7：1 周
- M8：3–4 周

合计约 13–19 周（不含调试坑）；M0 单独估 **3–5 天**。

## 协作约定
- **当前只对 M0 负责**：把 M0 跑通后停下来汇报，由用户决定继续 M1 还是别的优先级
- **架构层面预留 SMP/网络/动态链接的接口**：写 M0–M1 代码时不要做出"这辈子都不会有 SMP"或"内核里永远没有 socket"这种封死的假设；抽象层留出能后期插入的位置即可，**不要现在就把 SMP/网络/动态链接的实现写出来**
- 验收路径按 milestone 顺序走；不跳级
