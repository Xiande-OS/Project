# 接手指南（HANDOFF）

> 给新加入的 AI agent / 新会话 / 协作开发者读。
> 最近更新：2026-06-01（全面重写——旧版停留在"代码未开始、只做 M0"，已作废）

## 30 秒摘要
- 项目：**xiande-os**，Rust 写的 `no_std + alloc` 宏内核，2026 全国大学生计算机系统能力大赛 OS 设计赛 / 内核实现赛道参赛作品。
- 形态：主目标 RISC-V `riscv64gc`，跑 QEMU `virt` + OpenSBI；另有可运行的 LoongArch64 端口。
- 现状：**成熟内核**。能完整跑完大赛测试套件 `musl` + `glibc` 两变体（basic/lua/busybox/libctest/iperf/netperf + LTP + benchmarks），零 panic 跑到 SBI 关机。**不要**被旧文档的"M0/代码未开始"误导。
- libc：musl **和** glibc 都支持（早期设计说仅 musl，已推翻）。
- 用户：风扇滑翔翼（fang.gliding@gmail.com）。把任务交给云端 agent 跑，偏好**少问多报**——授权内自己决，带具体数字汇报。
- 协作分支：在 `claude/zealous-cannon-jaykV` 上开发并推送，**不要推 main**。该分支已与 main 分叉（各 ~50 提交），它是本任务的真相源。

## 一定要先读的
1. **[PROGRESS.md](PROGRESS.md)** — 当前阶段、已实现功能、自测/实测数字、已知问题、复现工作流。
2. **[DESIGN.md](DESIGN.md)** — 架构决策与"为什么"。注意顶部「现状」段：原始设计有几处已被推翻（async→协作式、musl-only→+glibc、栈 trampoline→vDSO、FAT32→ext4），决策日志有记录。
3. **本文件** — 怎么 build / run / 复现 / 协作。
4. `docs/shm-iozone-investigation.md` — SHM stub 的根因调查（一个有效的"为什么不修"记录）。

## 怎么 build
```sh
make all      # → 仓库根的 kernel-rv + kernel-la
```
- 用**评测机自带的 stable 工具链**即可（实测 stable 1.94.1，77s，零 unstable feature）。
- **故意不放 `rust-toolchain.toml`**（钉 channel 会触发 rustup 升级，评测机跨挂载点 rename 报 EXDEV → 构建失败）。见 `Makefile` 顶部长注释。
- 第三方 crate 全 vendor 在 `vendor/`，`cargo build --offline`，零联网。
- `kernel/Cargo.toml` 默认 feature = `contest`，所以 `make all` 直接出评测就绪内核。
- `prepare` 把 `cargo/` → `.cargo/`、`kernel/cargo/` → `kernel/.cargo/`（评测机会删隐藏目录），并 best-effort `rustup target add` riscv64/loongarch64（失败则 LA 退回 placeholder ELF）。

## 怎么 run / 怎么复现（单点是默认反射）
```sh
# 评测机的启动方式（见 README）：qemu-system-riscv64 -machine virt -kernel kernel-rv -m 1G ... 挂 ext4 测试盘

# 单点复现（30 秒一轮，改一行→增量编译→复现）：
bash scripts/mini-disk.sh /tmp/t.img "<busybox_testcode.sh 正文>"
bash scripts/run-mini.sh  /tmp/t.img 20
```
- `mini-disk.sh` 造一张只含 `busybox` + 你给的 `busybox_testcode.sh` 的 ext4；`EXTRA_FILES="a b"` 可多拷二进制。
- 依赖 `/home/user/testsuite-build/sdcard/riscv/musl/`。
- 全量只在两个时刻跑：关键修复并入主线前的回归、里程碑数字定型。

## 环境（云端容器是全新的，需自备）
- **QEMU 默认没有** → `apt-get install qemu-system-misc`（得到 8.2.2；比赛要 9.x，精确对齐得另编/下 9.x）。
- **测试盘默认没有** → 从 r2 取：
  - `r2.fangliding.workers.dev/114514`：GET `/` 列文件；有 `sdcard-riscv-staging.tgz`（11MB，musl+glibc，解到 `/home/user/testsuite-build/sdcard/riscv/`）、`riscv-{musl,glibc}-ltp.tgz.part-*`（LTP bin，分片，cat 后解压）、`la-*`、`rv-bench-bins.tgz`、预编译 `kernel-rv/kernel-la`、`r2.sh`(ls/put/get/rm)。
  - 注意：r2 上的预编译 `kernel-rv` 来自提交 `ddaf088`，**本地历史没有这个对象**——要对应本 checkout 必须自己 build。
- riscv std：首次 `make` 会 `rustup target add riscv64gc-unknown-none-elf`（需网络/镜像；Makefile 在国内会切 rustup 镜像）。

## 代码地图（`kernel/src`）
- `main.rs` kmain：初始化 → 铺 /bin /lib /etc /dev /sys → 挂盘 → contest_runner。
- `contest_runner.rs`：生成 `/init.sh`，枚举 musl/glibc 变体、bind 加载器、LTP 两遍调度、per-group 预算。**marker 只由测试脚本打**（内核打会污染评测 regex）。
- `syscall/mod.rs`（8081 行，最大）、`syscall/{nr,socket,sysv_ipc}.rs`。
- `task/mod.rs`（2024 行）：调度器、clone/fork/execve、**看门狗**、OOM/孤儿回收。
- `signal.rs`、`vdso.rs`、`sync/futex.rs`、`mm/`、`fs/`、`net/`、`drivers/`、`arch/{riscv64,loongarch64}`。

## 工作纪律（用户偏好，务必遵守）
- **真相高于一切**：能跑就跑，真 Linux/qemu-user 当裁判；区分"真窟窿"与"空花盆"（真 Linux 也 fail 的不修不绕）。
- **复现先于修复**：先有 30 秒可复现的 FAIL，再动键盘；修完同路径必须 FAIL→Pass。
- **绝不为分数作弊**：不按测例名特判、不塞假返回值、不注入伪输出、不硬编码测试盘路径。改动必须是真实 OS 特性。提交前自审：`grep -rni "测例名|Pass!|####|GROUP" kernel/src` 应为空（marker/正文不得出现在内核 `println!`）。
- **本机测试盘的调整 ≠ 提交的代码**：为调试改本机盘里的脚本可以，但提交的内核不得因此改行为（评测机用原始盘），且要主动披露差异。
- **数字口径稳定**：libctest 永远 /217 等，换口径要明说。
- **少问多报**：授权内自己决；每个 commit / 有意义的数字 / agent 完成 → 立即带数字汇报。
- **main 干净，worktree 隔离**：subagent 在 worktree 干活，评审后再 fast-forward。
- **高破坏性操作前停一下**（rm -rf / push --force / reset --hard / kill 长跑进程）。
- 高频反感词：应该、可能、差不多、我以为。高频要求：具体数字、具体测例名、具体 commit 哈希、可复现命令。

## 文档维护约定
- 完成 milestone / 改了状态 → 更新 PROGRESS.md。
- 做重大架构决策（尤其推翻旧决策）→ 在 DESIGN.md 决策日志追加（配日期），并改正文。
- 接手新会话 → 先读这几个 `.claude/` 文件再动代码。
