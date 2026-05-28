//! Static ELF loader.
//!
//! Parses an ELF64 (riscv) image and produces a `MemorySet` populated
//! with the PT_LOAD segments, plus a user stack.  For M3 we only handle
//! statically-linked ELFs; M6 adds PT_INTERP for ld-musl.

use alloc::vec::Vec;
use xmas_elf::program::{Flags, ProgramHeader, Type};
use xmas_elf::ElfFile;

use crate::mm::address::{VirtAddr, PAGE_SIZE};
use crate::mm::memory_set::{MemorySet, VmArea, VmPerm};

#[derive(Debug, Clone)]
pub struct LoadedElf {
    pub entry: usize,
    pub user_sp_top: usize,
    /// Top of mapped image; brk starts here (rounded up to a page).
    pub program_break: usize,
    /// Auxv-relevant: number and size of program headers, plus their VA.
    pub phdr_va: usize,
    pub phent: usize,
    pub phnum: usize,
}

/// Initial user-stack top. 2 MiB stack just under 0x4000_0000.
const USER_STACK_TOP: usize = 0x4000_0000;
const USER_STACK_SIZE: usize = 2 * 1024 * 1024;

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

    for i in 0..phnum {
        let ph = elf.program_header(i as u16).map_err(|_| "bad phdr")?;
        match ph.get_type().map_err(|_| "bad phdr type")? {
            Type::Load => {
                load_segment(&elf, &ph, image, ms, &mut max_end_va, ph_off, &mut phdr_va)?;
            }
            Type::Phdr => {
                // PT_PHDR vaddr (if present) tells us where the phdr table is mapped.
                if ph.virtual_addr() != 0 {
                    phdr_va = ph.virtual_addr() as usize;
                }
            }
            _ => {}
        }
    }

    // User stack.
    let sp_top = USER_STACK_TOP;
    let sp_bot = USER_STACK_TOP - USER_STACK_SIZE;
    let stack = VmArea::new(
        VirtAddr(sp_bot),
        VirtAddr(sp_top),
        VmPerm::R | VmPerm::W | VmPerm::U,
    );
    ms.push_user_area(stack, None);

    // Program break starts one page above the loaded image (page-aligned).
    let brk_base = (max_end_va + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    ms.brk_base = VirtAddr(brk_base);
    ms.brk_cur = VirtAddr(brk_base);

    Ok(LoadedElf {
        entry: header.pt2.entry_point() as usize,
        user_sp_top: sp_top,
        program_break: brk_base,
        phdr_va,
        phent,
        phnum,
    })
}

fn load_segment(
    elf: &ElfFile,
    ph: &ProgramHeader,
    image: &[u8],
    ms: &mut MemorySet,
    max_end_va: &mut usize,
    ph_off: usize,
    phdr_va: &mut usize,
) -> Result<(), &'static str> {
    let _ = elf;
    let va = ph.virtual_addr() as usize;
    let file_sz = ph.file_size() as usize;
    let mem_sz = ph.mem_size() as usize;
    let offset = ph.offset() as usize;
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

    let va_start = VirtAddr(va);
    let va_end = VirtAddr(va + mem_sz);

    // Copy file_sz bytes from the image, the rest is zero (BSS).
    let mut data = Vec::with_capacity(mem_sz);
    let copy = core::cmp::min(file_sz, image.len().saturating_sub(offset));
    data.extend_from_slice(&image[offset..offset + copy]);
    data.resize(mem_sz, 0);

    let area = VmArea::new(va_start, va_end, perm);
    ms.push_user_area(area, Some(&data));

    if va + mem_sz > *max_end_va {
        *max_end_va = va + mem_sz;
    }

    // Track where the phdr table is loaded (in the first segment that
    // contains ph_offset).
    if *phdr_va == 0 && offset <= ph_off && ph_off < offset + file_sz {
        *phdr_va = va + (ph_off - offset);
    }

    // Mark unused to silence the borrow checker on `_`.
    let _ = perm;
    Ok(())
}

#[allow(dead_code)]
fn write_flags(f: Flags) -> bool {
    f.is_write()
}
