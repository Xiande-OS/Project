# 进度（PROGRESS）

> 描述项目当前阶段、已完成的工作、进行中的工作、已知问题、下一步动作。每完成一个 milestone 或做出重大决策后更新。
> 最近更新：2026-06-01（全面重写——此前内容停留在 M0 时期，与实际进度严重脱节，已作废）

## 当前阶段
**成熟参赛内核**。立项时划的 M0–M8 已全部落地：内核能在 QEMU `virt`（OpenSBI）上完整跑完 2026 OS 大赛测试套件的 `musl` + `glibc` 两个变体，零 kernel panic 跑到 SBI 关机。另有可运行的 LoongArch64 端口。

> ⚠️ 早期文档（本文件旧版、HANDOFF/GOALS 旧版）说"当前焦点 = M0 / 代码未开始"——那是 2026-05-28 立项当天的状态，**早已作废**，不要据此判断进度。

### 本会话实测（容器内 ground truth，2026-06-01）
- `make all` 在 **stable Rust 1.94.1** 下 **77s** 编出两端产物，rc=0，零 unstable feature：
  - `kernel-rv`：RISC-V ELF，entry `0x80200000`，33 MB
  - `kernel-la`：**真 LoongArch ELF**（24 MB，不是 placeholder——本机有 `loongarch64-unknown-none` 的 std）
- 冒烟：boot → 挂载 ext4 `/mnt` → `busybox sh /init.sh` → fork/exec/pipe/uname 正常，2s。
- 单组实测：**lua-musl 9/9**。

## 已实现（功能面）
- **启动/内存**：Sv39 三级页表、buddy 帧分配器、内核 heap、从 DTB 读 RAM 大小（非硬编码 1 GiB；riscv64 用 a1 传入的 DTB 指针，loongarch64 直接扫低位 RAM 找 FDT magic）、内核高半区映射。
- **进程/调度**：`fork`/`clone`（精确解析 flag：CLONE_VM/THREAD/FS/FILES/SIGHAND/SETTLS）/`execve`；单 hart **协作式 + trap 边界抢占**调度（非 async）；per-syscall in-kernel 看门狗；OOM killer + 孤儿/线程风暴回收。
- **信号**：POSIX 信号投递、`rt_sigframe`、**vDSO** `__vdso_rt_sigreturn`（带 CFI 供 glibc unwind）、CPU fault → signal、fault-loop 断路器。
- **文件系统**：三层 VFS（Inode/Dentry/File）、**ext4 只读**（评测盘主路径）、fat32、tmpfs、devfs、procfs（`/proc/self/{exe,maps,status,ns,...}`）、pipe、AF_UNIX/socket、memfd seals、硬链接 nlink 跟踪。
- **syscall**：`nr.rs` 236 个编号；覆盖 fs/mm/进程/信号/网络 + SysV IPC（shm/msg/sem，注意 shm 目前 stub，见 `docs/shm-iozone-investigation.md`）、splice 族（splice/tee/vmsplice/sendfile）、process_vm_readv/writev、openat2、sendmmsg/recvmmsg、unshare、umask、ioprio、kcmp、name_to_handle_at、preadv2/pwritev2、fchdir 等。
- **网络**：smoltcp（virtio-net）+ 内核内 127.0.0.1 loopback；socket syscall；iperf/netperf 可跑。
- **动态链接**：静态 + 动态都支持（musl `ld-musl-riscv64.so.1`、glibc `ld-linux-riscv64-lp64d.so.1`），auxv 完整、PT_INTERP、按变体设 `LD_LIBRARY_PATH`。
- **双架构**：riscv64（主线）+ loongarch64（同一 crate，`arch/loongarch64` backend）。
- **评测驱动**（`contest_runner.rs`）：生成 `/init.sh`，按优先级跑各组；LTP 走两遍（精选白名单 + 全量扫尾），per-group 预算 + per-case `timeout -s KILL`；marker 只由测试脚本打，内核不打。

## 项目自测数字（README 口径，RV/QEMU virt——非本会话验证）
| Group | musl | glibc |
|---|---|---|
| basic | 32/32 | 32/32 |
| lua | 9/9 | 9/9 |
| busybox | 55/55 | 55/55 |
| libctest | 217/217 | 177/217 |
| iperf | 6/6 | 6/6 |
| netperf | 5/5 | 5/5 |

> glibc libctest 的 177 是"真 Linux + 真 glibc 在这套 musl 自家套件上的天花板"——剩下的 case 断言 musl 专有行为或要 glibc locale 数据，在真 Linux glibc 上也 fail。
> LTP 由评测驱动跑（两遍），是分值大头，但 README 表里没单列分数，这里也不臆造。

## 进行中 / 已知问题
- **【已修 2026-06-04】loongarch64 评测机崩溃（CI 出分、比赛机崩）**：现象是 CI（QEMU 8.2）正常出分，比赛机（更新的 QEMU）跑到一半 `[kernel-mode fault] ... ecode=0x8 ... svc=#220`（clone）后 pid=1 中招关机。
  - 根因：帧分配器把 RAM 末端当成硬编码 `MEMORY_END_DEFAULT=0xC000_0000`。该默认只对 QEMU 8.2 的 `virt` 布局成立（高位 RAM 节点在 `0x9000_0000`，size `0x3000_0000` → 末端 `0xC000_0000`）。**QEMU ≥ 9 把高位 RAM 基址下移到 `0x8000_0000`**，`-m 1G` 时真实末端是 `0xB000_0000`。沿用旧默认会让分配器在 `[0xB000_0000,0xC000_0000)` 这段未backing的空洞里发帧；run 深处帧用尽后 `fork()` 的逐页 `memcpy` 经直映窗口写到这种地址 → 内核态 ADE。CI 因 RAM 真到 `0xC000_0000` 而无事。
  - 修复（`mm/mod.rs`，commit `3e0f02d`）：loongarch64 扫低位 RAM 找 QEMU 载入的 FDT（直接启动不经寄存器传 DTB 指针），取**包含内核固定载入地址的那段 memory region** 的末端。任意 QEMU 都得到真实末端（-m 1G→`0xB000_0000`，-m 2G→`0xF000_0000`）。QEMU 8.2 自身 DTB 有 bug（memory `reg` 高 32 位被填成 0x2，节点声称 RAM 在 `~0x2_9000_0000`），这些假区间不跨内核地址 → 8.2 找不到匹配、回退到对 8.2 正确的 `0xC000_0000` 默认。riscv64 不变。
  - 验证：QEMU 10.0.8 `-m 1G` 全量 glibc-LA LTP 跑完零 kernel fault（修复前在第 2134 行关机），分数 4463 TPASS / 782 例 ≈ 镜像 CI（QEMU 8.2）的 4464 / 766；RV 重测 `0xC000_0000` + 10MHz 不变。
- **mallocstress 类 wedge（未修）**：全量评测跑到 LTP `mallocstress` 时卡死，既不继续也不关机（评测机现象）。
  - 诊断：per-syscall 看门狗只盯"单条 syscall 在内核里 >8s"；`mallocstress` 是"大量短 syscall"型，每次 `watchdog_arm` 重置锚点，逃过 8s 预算。最后兜底关机只在 pid 1（contest init）变 Zombie 时触发，而那时 init 还在 `wait4`，所以不关机 → 评测机一直 `正在评判`。
  - ground truth：本会话用 LTP 真二进制 + `-m 1G` **单独**跑 mallocstress 并未 wedge（3s 被 `timeout` SIGKILL，FAIL 打出，run 继续，rc=0 干净关机）→ 卡死与全量累积内存/状态相关，须在真语境复现。
  - 修复方向（供后续）：case 级"无前进"看门狗 + 不依赖 pid1 死亡的绝对 deadline 兜底关机。
  - 状态：用户 2026-06-01 明确"此次只更新文档、不动代码"，故未实现。

## 复现工作流（单点 30 秒）
```sh
make all                                   # 出 kernel-rv（stable 工具链即可）
bash scripts/mini-disk.sh /tmp/t.img "<testcode 正文>"   # 造一张只含一个测试的 ext4
bash scripts/run-mini.sh /tmp/t.img 20                   # 跑，20s 墙钟上限
```
依赖本机 `/home/user/testsuite-build/sdcard/riscv/musl/`（busybox 等）。该目录由 r2 的 `sdcard-riscv-staging.tgz` 解出；QEMU/工具链/测试盘见 HANDOFF.md「环境」。

## 历史里程碑
- 2026-05-28：立项 + 架构论证（M0–M8 路线图，见 GOALS/DESIGN）。
- 2026-05-28 晚：M0 完成（QEMU 上首行 `xiande-os booting on hart 0`）。
- 此后（详见 `git log`）：trap/内存/调度 → 用户态/syscall → busybox/VFS → 动态链接/futex → 块设备/ext4 → 网络/socket → glibc 兼容 → LTP 调度 → LoongArch 端口 → OOM/看门狗等健壮性。
- 现状：成熟参赛内核，两变体全套跑完零 panic。
