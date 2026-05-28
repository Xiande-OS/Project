# 进度（PROGRESS）

> 这个文件描述项目当前所处的阶段、已完成的工作、正在进行的工作、阻塞项与下一步动作。每完成一个 milestone 或做出重大决策后更新。
> 最近更新：2026-05-28（M0 完成）

## 当前阶段
**M0 完成 ✅**：Cargo workspace、`riscv64gc-unknown-none-elf` 交叉编译、`cargo xtask qemu` 自动化、kernel 在 QEMU virt 上通过 OpenSBI 启动并打印 `xiande-os booting on hart 0`，DTB 物理地址正确显示（0xbfe00000），随后 SBI `system_reset` 干净关机。
**下一阶段 = 等用户决定**：按 GOALS.md 顺序应该接 M1（trap / 内存 / 调度器骨架，单 hart），但按协作约定 M0 跑通后停下来汇报，由用户决定下一步优先级。

## 方向校准历史（2026-05-28 一天三轮）
1. 上午：立项，9 个 milestone，SMP-ready + 动态链接 + 网络（wget 终验收）
2. 下午早些：用户说"单核简单一点 跑得起 git 就行"，pivot 到 6 milestone 砍 SMP/网络/动态/async
3. 下午晚些：用户校准——"网络栈我还是要 静态/动态链接也是 只是留接口 demo 可以先不要 先把 demo 跑起来"。
   → **当前方案**：架构层面恢复到立项的全栈设计；实施层面只盯 M0，跑通后再说

## 已完成
- [x] 用户需求三轮澄清（见上）
- [x] 并行 3 个 Plan agent 调研（启动/内存/SMP、Linux ABI、I/O 与网络）
- [x] 关键技术选型敲定（见 [DESIGN.md](DESIGN.md)）
- [x] Milestone 划分 + 实施分期表（见 [GOALS.md](GOALS.md)、[DESIGN.md](DESIGN.md) 末尾"实施分期"段）
- [x] 协作准则与同步文件结构（本目录）确立
- [x] 协作记忆更新：补"少问多报"
- [x] **Milestone 0**：Cargo workspace + 交叉编译 + xtask 自动化 + boot.S + SBI 控制台
  - workspace `Cargo.toml`（resolver=2，members = `kernel`, `xtask`）
  - `rust-toolchain.toml` 钉 `nightly-2026-05-27` + `riscv64gc-unknown-none-elf` 目标
  - `kernel/`: `Cargo.toml` (sbi-rt 0.0.3, riscv 0.11)、`linker.ld` (`.text @ 0x80200000`)、`src/arch/riscv64/boot.S` 单 hart 入口（清 BSS、设栈、跳 kmain）、`src/main.rs` + `src/console.rs`（SBI legacy `console_putchar` 打印 + 干净 shutdown）
  - `xtask/`: `cargo xtask {build,qemu}`，支持 `--release` / `--debug` / `--smp N` / `--gdb`
  - workspace `.cargo/config.toml`: `xtask` alias + 仅作用于 `riscv64gc-unknown-none-elf` target 的链接 rustflags（host 构建不受影响）
  - kernel ELF 实测正确：`.text` 起 `0x80200000`，64K boot stack 在 `.bss`
  - **QEMU virt 实测输出**：`xiande-os booting on hart 0` / `dtb @ 0xbfe00000` / `M0: SBI console up. Halting.`，随后 SBI `system_reset(Shutdown, NoReason)` 干净退出

## 进行中
- 无。等用户决定是否开 M1。

## 阻塞 / 待用户决策
- **下一步 milestone 优先级**：默认按 GOALS.md 顺序进 M1（trap / 内存 / 调度器骨架），但 HANDOFF.md 写明"M0 跑通后必须停下汇报"，所以等用户拍板。
- 工具链注意：M0 没用到 `-Z build-std`，全靠 rustup 安装的 `riscv64gc-unknown-none-elf` 预编译 std component。M1 引内存分配/锁时如果需要 alloc 也可能继续不用 build-std；引入更深的 panic-abort customization 才考虑打开。

## 怎么跑（M0 当前状态）
```sh
# 一次到位
cargo xtask qemu

# 只编不跑
cargo xtask build

# 调试模式 / 多 hart 实验（M0 内核会把非 0 hart park 掉）
cargo xtask qemu --debug --smp 1
cargo xtask qemu --gdb            # 暂停等 gdb，:1234
```

## 下一步动作（建议，待用户确认）
M1 — trap / 内存 / 调度器骨架（单 hart）：
1. `kernel/src/arch/riscv64/trap.S` + `trap.rs`：`stvec` Direct 模式、`sscratch` 切栈、TrapFrame 保存全部 31 GPR
2. `kernel/src/mm/`：buddy 物理页分配器（先 `buddy_system_allocator` crate）、`PhysAddr`/`VirtAddr` newtype、`PageTable` 抽象（trait `PagingMode`，Sv39 起步）
3. 高半区跳转（M0 暂时 identity，M1 切到 `0xffff_ffff_8000_0000`）
4. SBI timer 设 10ms tick，最小调度器：idle + 两个内核线程交替打印
5. 除零/非法指令异常打 panic 信息
6. **验收**：两线程交替打印 + 异常 panic 路径正确

也可以按用户优先级跳到别的方向（例如先把用户态 ELF 加载 M3 做了），由用户拍板。

## 不做（M0 期间）
- 不实现 trap / 中断 / 内存管理 / 调度 / 用户态 / 文件系统 / 网络
- 不引 `buddy_system_allocator` / `xmas-elf` / `smoltcp` / `virtio-drivers` 等晚期 crate
- 模块目录（`mm/`, `sched/`, `fs/`, `net/`, `syscall/` 等）M0 不强制建立——只放 `arch/riscv64/` 就够

## 历史里程碑
- 2026-05-28（上午）：项目立项 + 架构论证完成
- 2026-05-28（下午）：方向两次校准，定为"全栈架构 + 仅 M0 实施"
- 2026-05-28（晚上）：**M0 完成**——首次 `xiande-os booting on hart 0` 出现在 QEMU virt 控制台

## 给接手 agent 的提示
- 项目目标和总体设计：先读 [GOALS.md](GOALS.md) 和 [DESIGN.md](DESIGN.md)
- 怎么开始 / 怎么协作：读 [HANDOFF.md](HANDOFF.md)
- **重要**：DESIGN.md 里描述的是完整架构，但 M0 阶段只实现"实施分期"表里标 ✅ 的那几项。不要因为 DESIGN.md 写了 smoltcp / SMP 就以为现在要写它们
- 协作节奏：每完成 milestone 后更新本文件；每个重大决策更新 DESIGN.md；**少问多报**——授权范围内自己决，决策结果写到 PROGRESS / DESIGN 即可
