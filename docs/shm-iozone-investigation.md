# SysV SHM + iozone regression — investigation notes

## Status
SHM syscalls are currently STUBBED to -1 (commit d88c214) because enabling them
crashed iozone's throughput mode and, on LoongArch, killed pid 1 (init) before
the run reached the glibc test groups. This doc records the root-cause work so a
future fix can re-enable SHM and reclaim the ~15 shm* LTP cases.

## Reproduced (real qemu-loongarch64, musl iozone built from the testsuite)
- `iozone -t 1` → completes (rc=119). `iozone -t 2`+ → "Killed" (deterministic).
- iozone `-t N` uses a `PTHREAD_PROCESS_SHARED` pthread_barrier_t placed in a
  SysV SHM segment (iozone.c:3986, alloc_mem(...,shared=1)); the N forked
  workers rendezvous on it. The crash is at that barrier.

## What WORKS (verified in isolation, all pass)
- SHM frame sharing across fork (shmget/shmat/IPC_RMID-while-attached, child writes visible).
- Atomic RMW on SHM across 4 forked children (count==4).
- Cross-process futex: parent→child FUTEX_WAKE, and sibling→sibling FUTEX_WAKE.
- Pure userspace cross-process spin (preemption switches processes correctly).
- futex keys by physical address, so shared frames hash to the same queue.

## The actual failure (futex-traced)
pthread_barrier_wait sequence for 2 children:
  child A: FUTEX_WAIT key=PA val=1 PARK
  child B: FUTEX_WAKE key=PA n=INT_MAX queued=1
  child A: RESUME result=Woken        <-- futex layer 100% correct
...but then NEITHER child's pthread_barrier_wait ever returns (no POST print,
no second FUTEX_WAIT logged), and ~8s later the watchdog kills them. So the
deadlock is in musl's barrier SECOND phase (the serial-thread / _b_count drain /
instance-reuse handshake), AFTER the count-futex succeeds. Not a fault — a hang.

## Next step for a fix
Needs musl pthread_barrier_wait.c source-level analysis (not available locally).
Likely candidates: the _b_count==0 re-check loop, or the vm-lock (__vm_wait)
instance handshake that the serial thread uses to wait for all others to leave.
Until then, SHM stays stubbed: iozone (×4 variants) + the glibc-LA column are
worth far more than the ~15 shm* LTP sub-cases.
