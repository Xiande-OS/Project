# 进度（PROGRESS）

> 这个文件描述项目当前所处的阶段、已完成的工作、正在进行的工作、阻塞项与下一步动作。每完成一个 milestone 或做出重大决策后更新。
> 最近更新：2026-05-28（第三轮校准后）

## 当前阶段
**M_design (rev. 3)**：架构论证已完成。仓库只有 `README.md` 与 `.claude/`。
**当前实施目标 = 仅 M0**（项目骨架 + SBI 控制台 "hello"）。其他 milestone 留架构接口，不写实现。

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

## 进行中
- [ ] **Milestone 0**：Cargo workspace 骨架 + cross-compile target + QEMU 启动脚本 + SBI 控制台 "hello"

## 阻塞 / 待用户决策
- 无。可以直接开 M0。

## 下一步动作（按顺序，仅 M0 范围）
1. 建立 Cargo workspace 根 `Cargo.toml`（resolver=2，workspace members = `kernel`, `xtask`）
2. 写 `rust-toolchain.toml` 钉 nightly + 加 `riscv64gc-unknown-none-elf` target
3. 建 `kernel/` crate：
   - `kernel/Cargo.toml`（`[package]` + `[dependencies]` 加 `sbi-rt`、`riscv`）
   - `kernel/.cargo/config.toml`：`target = "riscv64gc-unknown-none-elf"`、`rustflags = ["-C", "link-arg=-Tkernel/linker.ld"]`、`[unstable] build-std = ["core", "alloc", "compiler_builtins"]`
   - `kernel/linker.ld`：`.text @ 0x80200000`、`.rodata`、`.data`、`.bss.stack`、`__kernel_end` 等符号
   - `kernel/src/arch/riscv64/boot.S`：`_start` 单 hart 入口，设临时栈，跳到 `kmain(a0=hartid, a1=dtb)`
   - `kernel/src/main.rs`：`#![no_std] #![no_main]`、`#[panic_handler]`、`extern "C" fn kmain` 用 `sbi_rt::console_write_byte` 打 "xiande-os booting on hart {hartid}"
4. 建 `xtask/` crate：`xtask qemu` 子命令 — 调用 `cargo build -p kernel --release` → 用 `rust-objcopy` 抽 raw binary → `qemu-system-riscv64 -machine virt -nographic -bios default -kernel <binary>`
5. 跑 `cargo xtask qemu`，确认终端能看到 `xiande-os booting on hart 0`
6. M0 验收通过后，更新本文件，停下来汇报，等用户给下一步指示

## 不做（M0 期间）
- 不实现 trap / 中断 / 内存管理 / 调度 / 用户态 / 文件系统 / 网络
- 不引 `buddy_system_allocator` / `xmas-elf` / `smoltcp` / `virtio-drivers` 等晚期 crate
- 模块目录（`mm/`, `sched/`, `fs/`, `net/`, `syscall/` 等）M0 不强制建立——只放 `arch/riscv64/` 就够

## 历史里程碑
- 2026-05-28（上午）：项目立项 + 架构论证完成
- 2026-05-28（下午）：方向两次校准，定为"全栈架构 + 仅 M0 实施"

## 给接手 agent 的提示
- 项目目标和总体设计：先读 [GOALS.md](GOALS.md) 和 [DESIGN.md](DESIGN.md)
- 怎么开始 / 怎么协作：读 [HANDOFF.md](HANDOFF.md)
- **重要**：DESIGN.md 里描述的是完整架构，但 M0 阶段只实现"实施分期"表里标 ✅ 的那几项。不要因为 DESIGN.md 写了 smoltcp / SMP 就以为现在要写它们
- 协作节奏：每完成 milestone 后更新本文件；每个重大决策更新 DESIGN.md；**少问多报**——授权范围内自己决，决策结果写到 PROGRESS / DESIGN 即可
