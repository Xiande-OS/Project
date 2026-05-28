/*
 * xiande-os kernel linker script (M0)
 *
 * Memory layout (QEMU virt, S-mode after OpenSBI fw_jump):
 *   - OpenSBI lives at 0x8000_0000
 *   - Kernel entry at 0x8020_0000
 *
 * Note: M0 maps the kernel identity (low half). High-half mapping
 *       is M1 territory (paging brings us there).
 */

OUTPUT_ARCH(riscv)
OUTPUT_FORMAT("elf64-littleriscv")
ENTRY(_start)

BASE_ADDRESS = 0x80200000;

SECTIONS
{
    . = BASE_ADDRESS;
    __kernel_start = .;

    .text : ALIGN(4K) {
        __text_start = .;
        *(.text.entry)
        *(.text .text.*)
        . = ALIGN(4K);
        __text_end = .;
    }

    .rodata : ALIGN(4K) {
        __rodata_start = .;
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        . = ALIGN(4K);
        __rodata_end = .;
    }

    .data : ALIGN(4K) {
        __data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(4K);
        __data_end = .;
    }

    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        . = ALIGN(16);

        __boot_stack_bottom = .;
        . += 64K;
        __boot_stack_top = .;

        . = ALIGN(4K);
        __bss_end = .;
    }

    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
    }
}
