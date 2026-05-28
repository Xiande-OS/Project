# 接手指南（HANDOFF）

> 给新加入的 AI agent / 新会话的 Claude / 协作开发者读。

## 30 秒摘要
- 项目：**xiande-os**，用 Rust 在 RISC-V (riscv64gc) 上从零写一个 OS 内核
- 终极目标（远期）：在 QEMU `virt` 上跑普通的 riscv64 Linux 用户态程序，覆盖 **musl 静态 + 动态链接** 与 **网络程序（wget）**，架构层面支持 SMP
- **当前实施目标**：**仅 M0**——项目骨架 + SBI 控制台打印"hello"。后续 milestone 在架构里留好接口，但代码不写
- 定位：研究/实验型；不追求 Linux 100% 兼容，不支持 glibc
- 用户：风扇滑翔翼（fang.gliding@gmail.com）。她**会把任务交给云端 agent 跑**，希望 **少问多报**——授权范围内自己决，重大决策才同步到 `.claude/` 让其他 agent 接手
- 现状：架构定型（2026-05-28，经过三轮校准），**代码还未开始**

## 一定要先读的（按顺序）
1. **[GOALS.md](GOALS.md)** — 总目标、明确的非目标、9 个 milestone 的验收标准；注意"当前实施焦点 = M0"
2. **[DESIGN.md](DESIGN.md)** — 架构决策（Sv39、async kernel、三层 VFS、virtio-mmio、musl、sigreturn 栈 trampoline...）含所有"为什么"；末尾"实施分期"表标明哪些是 M0 要做的、哪些是后期
3. **[PROGRESS.md](PROGRESS.md)** — 当前阶段、下一步动作（仅 M0 范围）

读完这三个，你应该能直接接着写 M0 代码。

## 当前最易踩的坑：设计 ≠ 现在要写
- DESIGN.md 写了 smoltcp、SMP、async runtime、动态链接……**这些都是远期 milestone 的合约，M0 不要写它们**
- M0 的代码只要满足：能编译、能在 QEMU virt 用 SBI 打第一行字符串，就够了
- 模块抽象层面留好"以后能插入 SMP / 网络 / 动态链接"的位置就行——具体到 M0 通常意味着：写 trait 时不要把签名做成"永远单核"或"永远无 socket"

## 工作节奏（用户偏好）
- **少问多报**：决策自己拿，不要把每个小问题都甩给用户；进度则要勤汇报
- **每次开始有耗时的工具调用（多 agent、QEMU、build）前先一句话说明在干嘛**，不要静默
- **每完成 milestone 后**：更新 PROGRESS.md（移动 done 项、刷新"下一步动作"）；**M0 跑通后必须停下汇报，等用户决定下一步**
- **每次做重大架构决策后**：更新 DESIGN.md 的"决策日志"段（追加日期），如果改了已有决策就同步改正文
- **每次接手新会话**：先读这四个 .claude/ 文件再动代码

## 项目层关键约束
- 内核 `#![no_std]`，async/await 内核（远期），单地址空间宏内核
- 所有可阻塞 syscall 都将是 `async fn` + WaitQueue（远期；M0 用不到）
- 锁三层（RawSpinLock / SpinLock-with-IRQ / Mutex-sleep），有明确锁顺序约定
- per-CPU 数据通过 `tp` 寄存器 + 手工 offset 访问，**不**用 `#[thread_local]`（M0–M1 退化为 hart 0 only）
- 用 sbi-rt / riscv / virtio-drivers / smoltcp / fatfs / fdt / xmas-elf / cpio_reader / buddy_system_allocator 等成熟 crate，不重造轮子
- 工具链：内核 `riscv64gc-unknown-none-elf`；用户态 C 程序用 `riscv64-linux-musl-gcc`

## 当前断点（2026-05-28 晚）
**M0 已完成**——`cargo xtask qemu` 能在 QEMU virt 上看到 `xiande-os booting on hart 0`。
按协作约定停在这里等用户决定下一步：默认走 M1（trap / 内存 / 调度器骨架，单 hart），也可按用户优先级跳。
详见 [PROGRESS.md](PROGRESS.md) "下一步动作（建议，待用户确认）"段。

## 如果你遇到争议或需要决策
- **M0 范围内的小决策**（实现细节、文件组织、crate 版本）：自己拿主意，PROGRESS 里说一声即可
- **改动远期 milestone 设计**：写清权衡，**问用户**后才改 DESIGN.md 决策日志
- **绝不要**自作主张把"网络栈 / SMP / 动态链接"从 DESIGN 里删除——用户明确说过这些要留接口

## 想理解为什么选这套架构？
所有"为什么"都在 [DESIGN.md](DESIGN.md) 里，重要项再说一遍：
- **Sv39 而非 Sv48**：QEMU 上调试简单，39 位 512GB 用户空间够；Sv48 部分老 QEMU 有坑
- **musl 而非 glibc**：单文件 ld、依赖 syscall 少、不需要 nscd/clone3/rseq
- **async kernel**：smoltcp poll + 多 socket epoll 用 async 表达最自然
- **virtio-mmio 而非 PCI**：QEMU virt 默认 mmio，扫描简单
- **sbi-rt / virtio-drivers / smoltcp 这些 crate**：成熟、维护好、能省下大量底层代码量，把精力放在 Linux ABI 兼容上（这才是项目难点）
- **栈 sigreturn trampoline 而非 vDSO**：早期省工作量；vDSO 后期再做

## 工程基线（避免初学者错误）
- 初始栈 sp 必须 16 字节对齐
- AT_RANDOM 必须填入指向 16 可读字节的地址，否则 musl 启动 crash
- `writev` 必须早实现，musl printf 默认走它
- `mmap MAP_FIXED` 必须真覆盖（先 munmap 重叠区）
- futex WAIT 的 compare-and-block 必须原子，否则 lost wakeup
- 修改页表后必须 `sfence.vma`；跨 hart 用 SBI RFENCE
- MMIO 访问前后 `fence io,io`
- exit_group 必须杀整个 thread group（不是只杀当前线程）

## 联系约定
- 用户问"进度怎么样" → 直接引用 PROGRESS.md 的"当前阶段"和"已完成"
- 用户问"为什么这么设计" → 引用 DESIGN.md 对应小节
- 用户问"下一步做什么" → 引用 PROGRESS.md 的"下一步动作"
- 用户给方向变更 → 立即更新 PROGRESS.md + DESIGN.md 决策日志，再回话
