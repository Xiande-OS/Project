//! Minimal riscv64 vDSO.
//!
//! glibc cancels a thread (pthread_cancel) by sending SIGCANCEL (32) and
//! then running a *forced DWARF stack unwind* (`_Unwind_ForcedUnwind`)
//! from inside the signal handler, executing cleanup handlers until the
//! thread exits with PTHREAD_CANCELED. To unwind across the kernel-pushed
//! signal frame, libgcc's unwinder needs CFI (`.cfi_signal_frame` + the
//! register-recovery rules) associated with the PC that the kernel set as
//! the handler's return address (`ra`).
//!
//! On real riscv64 Linux the kernel points `ra` at the vDSO's
//! `__vdso_rt_sigreturn`, whose `.eh_frame` carries exactly that CFI, and
//! glibc finds the vDSO via the `AT_SYSINFO_EHDR` auxv entry. We replicate
//! that: a tiny prebuilt vDSO ELF (see `vdso/rt_sigreturn.S` + `vdso.lds`,
//! assembled with `riscv64-linux-gnu-{gcc,ld}`) is embedded here, mapped
//! read+execute into every user address space, advertised via
//! AT_SYSINFO_EHDR, and used as the handler restorer for glibc.
//!
//! musl does not need the vDSO (it uses its own `__restore_rt` trampoline
//! page, `signal::SIG_RESTORER_VA`); both remain installed so neither
//! libc regresses.
//!
//! The vDSO's single PT_LOAD maps file offset 0 -> vaddr 0, so mapping the
//! raw ELF bytes at `VDSO_BASE` makes the ELF header (which glibc parses
//! from AT_SYSINFO_EHDR), the program headers, and the `.eh_frame`/text
//! all land at the addresses their p_vaddr / st_value claim.

use crate::mm::memory_set::MemorySet;
use crate::mm::{VirtAddr, PAGE_SIZE};
use spin::Once;

/// Base virtual address at which the vDSO is mapped in every user address
/// space. Sits just above the signal-restorer page (0x5000_0000) and well
/// below the dynamic-linker base (0x10_0000_0000).
pub const VDSO_BASE: usize = 0x5000_1000;

/// The prebuilt vDSO ELF. Self-contained: no toolchain or network needed
/// at build/boot time. Rebuild with `kernel/src/vdso/build.sh` if the
/// rt_sigframe layout in `signal.rs` ever changes (the CFI offsets there
/// are tied to it).
static VDSO_ELF: &[u8] = include_bytes!("vdso/vdso.so");

struct VdsoInfo {
    /// Number of pages the single PT_LOAD occupies (>=1).
    pages: usize,
    /// Offset of `__vdso_rt_sigreturn` from VDSO_BASE (== its st_value,
    /// since the LOAD segment maps p_vaddr 0 at the base).
    sigreturn_off: usize,
}

static INFO: Once<VdsoInfo> = Once::new();

fn parse() -> VdsoInfo {
    let e = VDSO_ELF;
    // ELF64 header: e_phoff @ 0x20 (u64), e_phentsize @ 0x36 (u16),
    // e_phnum @ 0x38 (u16). Program header (PT_LOAD): p_type @ 0,
    // p_offset @ 8, p_vaddr @ 16, p_memsz @ 40.
    assert!(e.len() >= 64 && &e[0..4] == b"\x7fELF", "vDSO not an ELF");
    let phoff = rd_u64(e, 0x20) as usize;
    let phentsize = rd_u16(e, 0x36) as usize;
    let phnum = rd_u16(e, 0x38) as usize;

    // Find the (single) PT_LOAD and take its end vaddr as the mapped size.
    let mut max_end: usize = 0;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let p_type = rd_u32(e, ph);
        if p_type == 1 {
            // PT_LOAD
            let p_vaddr = rd_u64(e, ph + 16) as usize;
            let p_memsz = rd_u64(e, ph + 40) as usize;
            max_end = max_end.max(p_vaddr + p_memsz);
        }
    }
    assert!(max_end > 0, "vDSO has no PT_LOAD");
    let pages = (max_end + PAGE_SIZE - 1) / PAGE_SIZE;
    // The whole file must fit in the mapped region (it maps offset 0).
    assert!(
        e.len() <= pages * PAGE_SIZE,
        "vDSO file larger than its PT_LOAD"
    );

    let sigreturn_off = find_sym(e, "__vdso_rt_sigreturn")
        .expect("vDSO missing __vdso_rt_sigreturn");

    VdsoInfo { pages, sigreturn_off }
}

/// Locate a dynamic symbol's st_value by name. Walks PT_DYNAMIC to find
/// DT_SYMTAB / DT_STRTAB (both stored as p_vaddr-relative addresses which,
/// for this LOAD-at-0 vDSO, equal file offsets), then scans .dynsym.
fn find_sym(e: &[u8], name: &str) -> Option<usize> {
    let phoff = rd_u64(e, 0x20) as usize;
    let phentsize = rd_u16(e, 0x36) as usize;
    let phnum = rd_u16(e, 0x38) as usize;

    let mut dyn_off = 0usize;
    let mut dyn_sz = 0usize;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if rd_u32(e, ph) == 2 {
            // PT_DYNAMIC
            dyn_off = rd_u64(e, ph + 8) as usize; // p_offset
            dyn_sz = rd_u64(e, ph + 40) as usize; // p_memsz
            break;
        }
    }
    if dyn_sz == 0 {
        return None;
    }

    // Walk Elf64_Dyn entries: { i64 d_tag; u64 d_val } (16 bytes each).
    let mut symtab = 0usize;
    let mut strtab = 0usize;
    let mut syment = 24usize; // Elf64_Sym size
    let mut off = dyn_off;
    let end = dyn_off + dyn_sz;
    while off + 16 <= end {
        let tag = rd_u64(e, off) as i64;
        let val = rd_u64(e, off + 8) as usize;
        match tag {
            0 => break,        // DT_NULL
            5 => strtab = val, // DT_STRTAB
            6 => symtab = val, // DT_SYMTAB
            11 => syment = val, // DT_SYMENT
            _ => {}
        }
        off += 16;
    }
    if symtab == 0 || strtab == 0 {
        return None;
    }

    // Scan .dynsym. Elf64_Sym: st_name @ 0 (u32), st_value @ 8 (u64).
    // We don't have the symtab byte-length directly; stop at strtab (it
    // immediately follows .dynsym in our vdso.lds) or end of file.
    let sym_end = if strtab > symtab { strtab } else { e.len() };
    let mut s = symtab;
    while s + syment <= sym_end {
        let st_name = rd_u32(e, s) as usize;
        if st_name != 0 {
            let nm = cstr(e, strtab + st_name);
            if nm == name.as_bytes() {
                return Some(rd_u64(e, s + 8) as usize);
            }
        }
        s += syment;
    }
    None
}

fn cstr(e: &[u8], off: usize) -> &[u8] {
    let mut end = off;
    while end < e.len() && e[end] != 0 {
        end += 1;
    }
    &e[off..end]
}

fn rd_u16(e: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([e[off], e[off + 1]])
}
fn rd_u32(e: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([e[off], e[off + 1], e[off + 2], e[off + 3]])
}
fn rd_u64(e: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&e[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Parse the embedded vDSO once at boot so per-exec mapping is cheap and
/// any layout problem panics early rather than mid-contest.
pub fn init() {
    INFO.call_once(parse);
}

fn info() -> &'static VdsoInfo {
    INFO.call_once(parse)
}

/// Entry point glibc's unwinder must see as the handler return address.
pub fn sigreturn_entry() -> usize {
    VDSO_BASE + info().sigreturn_off
}

/// Map the vDSO read+execute into the given address space. Mirrors the
/// restorer page: the bytes are copied into freshly allocated frames, so
/// no two address spaces share the (immutable) vDSO pages — simple and
/// correct, at the cost of a few KiB per process.
pub fn install(ms: &mut MemorySet) {
    let nfo = info();
    // map_user_rx_page handles a single page; for a multi-page vDSO we map
    // page by page. In practice the LOAD is < 4 KiB so this is one page.
    for p in 0..nfo.pages {
        let va = VDSO_BASE + p * PAGE_SIZE;
        let start = p * PAGE_SIZE;
        let end = core::cmp::min(start + PAGE_SIZE, VDSO_ELF.len());
        let slice: &[u8] = if start < VDSO_ELF.len() {
            &VDSO_ELF[start..end]
        } else {
            &[]
        };
        ms.map_user_rx_page(VirtAddr(va), slice);
    }
}
