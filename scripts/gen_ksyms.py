#!/usr/bin/env python3
"""Generate a compact in-kernel symbol table ("ksyms") blob from a linked
kernel ELF, so the kernel can print `function+offset` for a fault/panic PC
*itself* — no addr2line, no matching toolchain. This is what makes a contest
crash log debuggable even though the grader's rustc (and thus .text layout)
may differ from any local build.

Parses the ELF's .symtab directly (no nm/objdump dependency, any target arch),
keeps STT_FUNC symbols with a nonzero address, strips the Rust legacy-mangling
hash suffix for readable names, and writes a sorted blob:

    u32  magic = 0x4B53594D ('KSYM' LE)
    u32  count
    u64  addr[count]        (ascending)
    u32  name_off[count]    (offset into strtab)
    u32  strtab_len
    u8   strtab[strtab_len] (NUL-terminated names)

Embedding it in .rodata (after .text in the link) does not move any .text
address, so a blob generated from pass 1 correctly describes pass 2.
"""
import sys, struct, re

STT_FUNC = 2

def u16(b, o): return struct.unpack_from('<H', b, o)[0]
def u32(b, o): return struct.unpack_from('<I', b, o)[0]
def u64(b, o): return struct.unpack_from('<Q', b, o)[0]

def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: gen_ksyms.py <kernel.elf> <out.bin>\n")
        return 2
    elf = open(sys.argv[1], 'rb').read()
    if elf[:4] != b'\x7fELF' or elf[4] != 2:   # 64-bit only
        sys.stderr.write("gen_ksyms: not a 64-bit ELF\n")
        return 1
    # ELF64 header: e_shoff@40 (u64), e_shentsize@58 (u16), e_shnum@60 (u16).
    e_shoff = u64(elf, 0x28)
    e_shentsize = u16(elf, 0x3a)
    e_shnum = u16(elf, 0x3c)

    symtab = strtab = None
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        sh_type = u32(elf, sh + 4)
        if sh_type == 2:  # SHT_SYMTAB
            sym_off = u64(elf, sh + 0x18)
            sym_size = u64(elf, sh + 0x20)
            sym_link = u32(elf, sh + 0x28)  # -> strtab section index
            symtab = (sym_off, sym_size)
            ls = e_shoff + sym_link * e_shentsize
            strtab = (u64(elf, ls + 0x18), u64(elf, ls + 0x20))
            break
    if not symtab or not strtab:
        sys.stderr.write("gen_ksyms: no .symtab\n")
        return 1

    sym_off, sym_size = symtab
    str_off, str_size = strtab
    strbytes = elf[str_off:str_off + str_size]

    def name_at(off):
        end = strbytes.find(b'\x00', off)
        return strbytes[off:end].decode('latin-1')

    # _ZN..17h<16hex>E  ->  drop the hash; also strip leading _ZN/ trailing E
    hash_re = re.compile(r'17h[0-9a-f]{16}E$')

    syms = {}
    n = sym_size // 24  # Elf64_Sym is 24 bytes
    for i in range(n):
        e = sym_off + i * 24
        st_name = u32(elf, e + 0)
        st_info = elf[e + 4]
        st_value = u64(elf, e + 8)
        if (st_info & 0xf) != STT_FUNC or st_value == 0:
            continue
        raw = name_at(st_name)
        if not raw:
            continue
        raw = hash_re.sub('', raw)
        # keep the smallest-address occurrence per address (dedup)
        if st_value not in syms or len(raw) < len(syms[st_value]):
            syms[st_value] = raw

    items = sorted(syms.items())
    count = len(items)

    strtab_out = bytearray()
    name_offs = []
    for _, name in items:
        name_offs.append(len(strtab_out))
        strtab_out += name.encode('latin-1') + b'\x00'

    out = bytearray()
    out += struct.pack('<II', 0x4B53594D, count)
    for addr, _ in items:
        out += struct.pack('<Q', addr)
    for off in name_offs:
        out += struct.pack('<I', off)
    out += struct.pack('<I', len(strtab_out))
    out += strtab_out

    open(sys.argv[2], 'wb').write(out)
    sys.stderr.write("gen_ksyms: %d symbols, %d bytes\n" % (count, len(out)))
    return 0

if __name__ == '__main__':
    sys.exit(main())
