# Non-LTP benchmark gap — root causes & status

The contest rank gap to #1 is almost entirely the **performance-benchmark**
groups (LTP is log-weighted now). This file records what each one actually
needs, from local reproduction with the `single_bench` harness against the
official combined disk (`ci/prep-fulldisk.sh`).

Reproduce one group:
```
XIANDE_BENCH=<group> XIANDE_LIBC=<musl|glibc> [XIANDE_DBG=1 XIANDE_ONLY=<substr> SYSTRACE=1 XIANDE_CMDTO=<s>] \
  cargo build --release -p kernel --target riscv64gc-unknown-none-elf --features single_bench
# boot kernel-rv-bench against sdcard-rv.img (x0) + a 512M scratch (x1)
```

## FIXED (on dev-n, locally verified)
- **libcbench-glibc** — glibc NPTL caches and reuses the *same* thread-stack
  address; our deferred stack-reclaim unmapped that address once the backlog
  passed the high-water mark, killing a now-live stack → SIGSEGV → group
  truncated before its END marker. Fix: `MemorySet::cancel_stack_reclaim()` on
  thread creation. Verified: 0 SIGSEGV, all 26 sub-benches emit timings (was
  ~16). (commit: "cancel stale stack-reclaim …")
- **pselect6(nfds==0)** — `select(0,…,timeout)` (portable sleep/yield idiom)
  returned 0 instantly, ignoring the timeout → 100% busy-spin that, on our
  cooperative single-core scheduler, starved peers. Now parks for a yield
  slice / the real timeout. (commit: "select(nfds=0) must yield/sleep …")

## OPEN — deep scheduler / IPC work (parked; need a focused, CI-gated session)

### lmbench (−288, the biggest single group)
- Latency micro-benches up to CMD 14 all pass with good numbers (syscall 3.9µs
  < baseline 9.25µs, etc.). The group dies at **CMD 15 `lat_pipe`**.
- `lat_pipe` forks a child and ping-pongs a byte through two pipes. Trace shows
  both ends actively `read`/`write` (not deadlocked) — but the measurement
  never completes within 90s **and** the per-command `busybox timeout` watchdog
  never fires (no rc=137). I.e. the 2-process IPC loop **monopolises the single
  core** and starves the watchdog (parked in `nanosleep`) and the driver.
- Root issue: scheduler fairness / timer-wake under a runaway tight IPC loop.
  `pick_ready` is lowest-pid-first (not round-robin), and the cooperative
  scheduler only switches on block. `lat_ctx` (context-switch) and `lat_proc`
  (fork/exec storm) will hit the same wall.
- Next: confirm whether `nanosleep`/`itimer` reliably wakes the watchdog while
  two peers ping-pong (instrument `wake_expired_sleepers`); consider bounding
  runaway escaped children. High value but the scheduler is delicate — must be
  CI-gated.

### iozone (−160)
- `-a` auto test produces full throughput numbers. The scored `-t 4` throughput
  tests need SHM (currently stubbed) for the cross-process barrier.
- With SHM re-enabled: `fork()` already shares shmat'd frames correctly, and the
  pselect6 busy-spin (above) is fixed — but the **4-worker barrier rendezvous
  still doesn't complete**: the master forks workers 10–13, yet only some reach
  the `select(0,…)` barrier poll; the others never arrive. Deeper multi-worker
  sync/scheduling bug.
- SHM kept **stubbed** meanwhile (so iozone cleanly falls back to 0 instead of
  hanging — a hang risks cascading, which is why it was disabled originally).
  Re-enable SHM only together with the rendezvous fix.

### iperf (−38, musl) / netperf (−30, glibc)
- Both are loopback (127.0.0.1) client/server: `iperf3 -s -p 5001 -D` then
  `iperf3 -c …`; `netserver -D -L 127.0.0.1 &` then `netperf -H 127.0.0.1 …`.
- Each fails on exactly one libc. iperf3 `-D` daemonises (double-fork+setsid →
  own session); netperf `-D` stays foreground. Suspect a loopback TCP/UDP path
  and/or the daemon-session lifecycle vs `kill_session`. Needs the harness to
  reproduce one cell and trace the connect/accept.

### cyclictest (−32)
- Not yet reproduced. RT-latency loop (`clock_nanosleep` ABS + SCHED_FIFO).
