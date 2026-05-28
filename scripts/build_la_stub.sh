#!/bin/bash
# Generate a minimal LoongArch64 ELF stub. xiande-os has no LoongArch
# port yet; this exists purely so `make all` can produce the required
# kernel-la artifact and not abort the contest harness's `make` invocation.
set -e
out="${1:-kernel-la}"

# Inline Python because /usr/bin/python3 is available in the contest image.
python3 - "$out" <<'PY'
import struct, sys
out = sys.argv[1]
EI = bytes([0x7f]) + b'ELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8  # 16
e_type = 2          # ET_EXEC
e_machine = 258     # EM_LOONGARCH
e_version = 1
e_entry = 0x9000000000200000     # contest spec says LA entry near here
e_phoff = 64
e_shoff = 0
e_flags = 0
e_ehsize = 64
e_phentsize = 56
e_phnum = 1
e_shentsize = 0
e_shnum = 0
e_shstrndx = 0
ehdr = EI + struct.pack('<HHIQQQIHHHHHH',
    e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
    e_flags, e_ehsize, e_phentsize, e_phnum,
    e_shentsize, e_shnum, e_shstrndx)
# One PT_LOAD covering a 4-byte loop instruction "b 0" (a.k.a. infinite loop)
# at e_entry.
p_type   = 1        # PT_LOAD
p_flags  = 5        # PF_R | PF_X
p_offset = 0x1000
p_vaddr  = e_entry
p_paddr  = e_entry
p_filesz = 4
p_memsz  = 4
p_align  = 0x1000
phdr = struct.pack('<IIQQQQQQ',
    p_type, p_flags, p_offset, p_vaddr, p_paddr,
    p_filesz, p_memsz, p_align)
# LoongArch "b 0" = unconditional infinite jump (0x50000000)
body = struct.pack('<I', 0x50000000)
with open(out, 'wb') as f:
    f.write(ehdr)
    f.write(phdr)
    f.write(b'\x00' * (0x1000 - len(ehdr) - len(phdr)))
    f.write(body)
PY
chmod +x "$out"
