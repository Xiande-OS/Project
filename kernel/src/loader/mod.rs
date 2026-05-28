//! Static + dynamic ELF loader (M3 + M6).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use xmas_elf::program::{ProgramHeader, Type};
use xmas_elf::ElfFile;

use crate::fs;
use crate::mm::address::{VirtAddr, PAGE_SIZE};
use crate::mm::memory_set::{MemorySet, VmArea, VmPerm};

#[derive(Debug, Clone)]
pub struct LoadedElf {
    /// Initial PC the kernel should jump to. For dynamic ELFs this is
    /// the interpreter's entry; for static ELFs it's the program entry.
    pub entry: usize,
    pub user_sp_top: usize,
    pub program_break: usize,
    pub phdr_va: usize,
    pub phent: usize,
    pub phnum: usize,
    pub program_entry: usize,
    /// Set when PT_INTERP loaded an interpreter; this is the base it
    /// was relocated to. 0 for static.
    pub interp_base: usize,
}

const USER_STACK_TOP: usize = 0x4000_0000;
const USER_STACK_SIZE: usize = 8 * 1024 * 1024;
/// Base address we relocate the dynamic linker to. Must stay below the
/// Sv39 user-half ceiling (0x40_0000_0000). Sits well above our 8 MiB
/// user stack (which ends at 0x4000_0000).
const INTERP_BASE: usize = 0x10_0000_0000;

pub fn load_elf(image: &[u8], ms: &mut MemorySet) -> Result<LoadedElf, &'static str> {
    let elf = ElfFile::new(image).map_err(|_| "bad ELF")?;
    let header = elf.header;
    if header.pt1.magic != [0x7f, b'E', b'L', b'F'] {
        return Err("not an ELF");
    }
    if header.pt2.machine().as_machine() != xmas_elf::header::Machine::RISC_V {
        return Err("ELF not RISC-V");
    }

    let mut max_end_va = 0usize;
    let mut phdr_va = 0usize;
    let phent = header.pt2.ph_entry_size() as usize;
    let phnum = header.pt2.ph_count() as usize;
    let ph_off = header.pt2.ph_offset() as usize;
    let mut interp_path: Option<String> = None;

    for i in 0..phnum {
        let ph = elf.program_header(i as u16).map_err(|_| "bad phdr")?;
        match ph.get_type().map_err(|_| "bad phdr type")? {
            Type::Load => {
                load_segment(&ph, image, ms, &mut max_end_va, ph_off, &mut phdr_va, 0)?;
            }
            Type::Phdr => {
                if ph.virtual_addr() != 0 {
                    phdr_va = ph.virtual_addr() as usize;
                }
            }
            Type::Interp => {
                let off = ph.offset() as usize;
                let len = ph.file_size() as usize;
                let raw = &image[off..off + len];
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                interp_path = core::str::from_utf8(&raw[..end])
                    .ok()
                    .map(String::from);
            }
            _ => {}
        }
    }

    // Stack.
    let sp_top = USER_STACK_TOP;
    let sp_bot = USER_STACK_TOP - USER_STACK_SIZE;
    let stack = VmArea::new(
        VirtAddr(sp_bot),
        VirtAddr(sp_top),
        VmPerm::R | VmPerm::W | VmPerm::U,
    );
    ms.push_user_area(stack, None);

    let brk_base = (max_end_va + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    ms.brk_base = VirtAddr(brk_base);
    ms.brk_cur = VirtAddr(brk_base);

    let program_entry = header.pt2.entry_point() as usize;
    let mut entry = program_entry;
    let mut interp_base = 0usize;

    if let Some(path) = interp_path {
        let interp_inode = fs::lookup_path(fs::root(), &path).map_err(|_| "PT_INTERP missing")?;
        let size = interp_inode.size() as usize;
        let mut blob = alloc::vec![0u8; size];
        interp_inode.read_at(0, &mut blob).map_err(|_| "PT_INTERP read")?;
        let aligned = aligned_copy(&blob);
        let (interp_entry, base) = load_interpreter(&aligned, ms, INTERP_BASE)?;
        entry = interp_entry;
        interp_base = base;
    }

    Ok(LoadedElf {
        entry,
        user_sp_top: sp_top,
        program_break: brk_base,
        phdr_va,
        phent,
        phnum,
        program_entry,
        interp_base,
    })
}

fn load_interpreter(
    image: &[u8],
    ms: &mut MemorySet,
    base: usize,
) -> Result<(usize, usize), &'static str> {
    let elf = ElfFile::new(image).map_err(|_| "bad interp ELF")?;
    let header = elf.header;
    let phnum = header.pt2.ph_count() as usize;
    let mut dummy_phdr = 0usize;
    let mut max_end = 0usize;
    for i in 0..phnum {
        let ph = elf.program_header(i as u16).map_err(|_| "bad interp phdr")?;
        if let Ok(Type::Load) = ph.get_type() {
            load_segment(&ph, image, ms, &mut max_end, 0, &mut dummy_phdr, base)?;
        }
    }
    let entry = base + header.pt2.entry_point() as usize;
    Ok((entry, base))
}

fn load_segment(
    ph: &ProgramHeader,
    image: &[u8],
    ms: &mut MemorySet,
    max_end_va: &mut usize,
    ph_off: usize,
    phdr_va: &mut usize,
    base_offset: usize,
) -> Result<(), &'static str> {
    let va = ph.virtual_addr() as usize + base_offset;
    let file_sz = ph.file_size() as usize;
    let mem_sz = ph.mem_size() as usize;
    let file_off = ph.offset() as usize;
    let flags = ph.flags();

    if mem_sz == 0 {
        return Ok(());
    }

    let mut perm = VmPerm::U;
    if flags.is_read() {
        perm |= VmPerm::R;
    }
    if flags.is_write() {
        perm |= VmPerm::W;
    }
    if flags.is_execute() {
        perm |= VmPerm::X;
    }

    let page_offset = va & (PAGE_SIZE - 1);
    let va_start = VirtAddr(va & !(PAGE_SIZE - 1));
    let va_end_raw = va + mem_sz;
    let va_end = VirtAddr((va_end_raw + PAGE_SIZE - 1) & !(PAGE_SIZE - 1));

    let total = va_end.0 - va_start.0;
    let mut buf = Vec::with_capacity(total);
    buf.resize(total, 0);
    let file_avail = core::cmp::min(file_sz, image.len().saturating_sub(file_off));
    buf[page_offset..page_offset + file_avail]
        .copy_from_slice(&image[file_off..file_off + file_avail]);

    let area = VmArea::new(va_start, va_end, perm);
    ms.push_user_area(area, Some(&buf));

    if va + mem_sz > *max_end_va {
        *max_end_va = va + mem_sz;
    }

    if base_offset == 0
        && *phdr_va == 0
        && file_off <= ph_off
        && ph_off < file_off + file_sz
    {
        *phdr_va = va + (ph_off - file_off);
    }

    Ok(())
}

fn aligned_copy(src: &[u8]) -> Vec<u8> {
    let nwords = (src.len() + 7) / 8;
    let mut words = alloc::vec![0u64; nwords];
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), words.as_mut_ptr() as *mut u8, src.len());
    }
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    unsafe {
        core::ptr::copy_nonoverlapping(words.as_ptr() as *const u8, out.as_mut_ptr(), src.len());
        out.set_len(src.len());
    }
    drop(words);
    out
}

// Re-export so users can keep Arc<dyn Inode> abstractions if needed later.
#[allow(dead_code)]
pub fn _link_unused(_: Arc<dyn fs::Inode>) {}
