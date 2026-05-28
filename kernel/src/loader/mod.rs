//! Static ELF loader.

use alloc::vec::Vec;
use xmas_elf::program::{ProgramHeader, Type};
use xmas_elf::ElfFile;

use crate::mm::address::{VirtAddr, PAGE_SIZE};
use crate::mm::memory_set::{MemorySet, VmArea, VmPerm};

#[derive(Debug, Clone)]
pub struct LoadedElf {
    pub entry: usize,
    pub user_sp_top: usize,
    pub program_break: usize,
    pub phdr_va: usize,
    pub phent: usize,
    pub phnum: usize,
}

const USER_STACK_TOP: usize = 0x4000_0000;
const USER_STACK_SIZE: usize = 8 * 1024 * 1024;

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
                load_segment(&ph, image, ms, &mut max_end_va, ph_off, &mut phdr_va)?;
            }
            Type::Phdr => {
                if ph.virtual_addr() != 0 {
                    phdr_va = ph.virtual_addr() as usize;
                }
            }
            _ => {}
        }
    }

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
    ph: &ProgramHeader,
    image: &[u8],
    ms: &mut MemorySet,
    max_end_va: &mut usize,
    ph_off: usize,
    phdr_va: &mut usize,
) -> Result<(), &'static str> {
    let va = ph.virtual_addr() as usize;
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

    // For a segment with non-page-aligned VA, the first page's
    // contents are: [zeros up to (va & 0xfff)] then [file bytes].
    // mem_sz extends with .bss zeros after file_sz.
    let page_offset = va & (PAGE_SIZE - 1);
    let va_start = VirtAddr(va & !(PAGE_SIZE - 1));
    let va_end_raw = va + mem_sz;
    let va_end = VirtAddr((va_end_raw + PAGE_SIZE - 1) & !(PAGE_SIZE - 1));

    // Build the buffer that, when placed at va_start, reproduces the
    // segment's expected memory image.
    let total = va_end.0 - va_start.0;
    let mut buf = Vec::with_capacity(total);
    buf.resize(total, 0);
    let file_avail = core::cmp::min(file_sz, image.len().saturating_sub(file_off));
    buf[page_offset..page_offset + file_avail]
        .copy_from_slice(&image[file_off..file_off + file_avail]);
    // BSS portion stays zero (already from resize above).

    let area = VmArea::new(va_start, va_end, perm);
    ms.push_user_area(area, Some(&buf));

    if va + mem_sz > *max_end_va {
        *max_end_va = va + mem_sz;
    }

    if *phdr_va == 0 && file_off <= ph_off && ph_off < file_off + file_sz {
        *phdr_va = va + (ph_off - file_off);
    }

    Ok(())
}
