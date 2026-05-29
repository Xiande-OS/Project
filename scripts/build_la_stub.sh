#!/bin/bash
# Generate a minimal LoongArch64 ELF stub. xiande-os has no LoongArch port
# yet, but the contest harness still boots `kernel-la` under QEMU. Without
# a working shutdown the LA QEMU process spins forever and the grader
# waits until its outer wall-clock cap, surfaced as
# "评测时间过长" in the contest UI. This stub instead jumps straight to
# QEMU's ACPI GED SLEEP_CTL register at the LA virt board's MMIO address,
# triggering a clean qemu_system_shutdown_request() so the LA process
# exits in ~50ms. We score 0 on LA (we don't implement anything) either
# way; the difference is we no longer eat the grader's timeout budget.
#
# The body is 24 LoongArch instructions, hand-verified by assembling
# scripts/la_stub.S with loongarch64-linux-gnu-as inside the contest
# docker image (zhouzhouyi/os-contest:20260510), running the resulting
# ELF under qemu-system-loongarch64 9.2.1 / 10.0.2, and confirming the
# QEMU process exits with rc=0 in ~50ms. Source is preserved at
# scripts/la_stub.S for anyone who wants to regenerate / extend it.

set -e
out="${1:-kernel-la}"

python3 - "$out" <<'PY'
import struct, sys
out = sys.argv[1]

# ----- ELF header (LoongArch64 ET_EXEC, EM_LOONGARCH=258) -----
EI = bytes([0x7f]) + b'ELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8
e_entry = 0x9000000000200000     # contest spec puts LA entry near here
e_phoff = 64
ehdr = EI + struct.pack(
    '<HHIQQQIHHHHHH',
    2,           # e_type   = ET_EXEC
    258,         # e_machine = EM_LOONGARCH
    1,           # e_version
    e_entry,
    e_phoff,
    0,           # e_shoff
    0,           # e_flags
    64,          # e_ehsize
    56,          # e_phentsize
    1,           # e_phnum
    0, 0, 0,
)

# ----- One PT_LOAD covering the shutdown trampoline -----
# Each u32 is one LoongArch little-endian instruction; produced by
# loongarch64-linux-gnu-as on scripts/la_stub.S, verified empirically.
instr_words = [
    0x02c0d006,  # li.d        a2, 0x34         (SLP_TYP=5<<2 | SLP_EN=1<<5)
    # 1) try GED SLEEP_CTL at raw physical 0x100E001C (CSR_CRMD.DA boot mode)
    0x14201c05,  # lu12i.w     a1, 0x100E0
    0x038070a5,  # ori         a1, a1, 0x01C
    0x290000a6,  # st.b        a2, a1, 0
    # 2) try via DMW1 vseg 0x9 (cacheable map the QEMU LA boot path presets)
    0x14201c05,  # lu12i.w     a1, 0x100E0
    0x038070a5,  # ori         a1, a1, 0x01C
    0x032400a5,  # lu52i.d     a1, a1, -1792   (top12 = 0x900)
    0x290000a6,  # st.b        a2, a1, 0
    # 3) explicitly set up DMW0/DMW1 + switch CRMD to PG mode, then write via DMW0
    0x14000004,  # lu12i.w     a0, 0
    0x03804484,  # ori         a0, a0, 0x11    (MAT=uncached | PLV0 enable)
    0x03200084,  # lu52i.d     a0, a0, -2048   (top12 = 0x800)
    0x04060024,  # csrwr       a0, 0x180       (CSR_DMW0 = 0x8000000000000011)
    0x14000004,  # lu12i.w     a0, 0
    0x03804484,  # ori         a0, a0, 0x11
    0x03240084,  # lu52i.d     a0, a0, -1792   (top12 = 0x900)
    0x04060424,  # csrwr       a0, 0x181       (CSR_DMW1 = 0x9000000000000011)
    0x02c04004,  # li.d        a0, 0x10        (PG=1, DA=0, PLV=0, IE=0)
    0x04000024,  # csrwr       a0, 0x0         (CSR_CRMD)
    0x14201c05,  # lu12i.w     a1, 0x100E0
    0x038070a5,  # ori         a1, a1, 0x01C
    0x032000a5,  # lu52i.d     a1, a1, -2048   (top12 = 0x800 -> uncached MMIO)
    0x290000a6,  # st.b        a2, a1, 0
    # Fallback: if no shutdown trigger fired (older QEMU, no ACPI GED, ...),
    # idle to avoid burning 100% CPU and loop forever.
    0x06488000,  # idle        0
    0x53ffffff,  # b           -4
]
body = b''.join(struct.pack('<I', w) for w in instr_words)

p_offset = 0x1000
phdr = struct.pack(
    '<IIQQQQQQ',
    1,           # p_type = PT_LOAD
    5,           # p_flags = PF_R | PF_X
    p_offset,
    e_entry,     # p_vaddr
    e_entry,     # p_paddr (QEMU LA loader masks high bits to land in RAM)
    len(body),
    len(body),
    0x1000,
)

with open(out, 'wb') as f:
    f.write(ehdr)
    f.write(phdr)
    f.write(b'\x00' * (p_offset - len(ehdr) - len(phdr)))
    f.write(body)
PY
chmod +x "$out"
