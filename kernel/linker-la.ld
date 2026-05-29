/*
 * xiande-os kernel linker script — LoongArch64.
 *
 * Memory layout (QEMU `virt`, direct-boot via -kernel):
 *   - QEMU enters the ELF at its (virtual) entry with DMW0 active, mapping
 *     0x9000_0000_0000_0000 -> PA 0 cached.
 *   - The QEMU `virt` machine splits RAM: 256 MiB low at PA 0, the rest
 *     high at PA 0x9000_0000. Our kernel image (with its 256 MiB static
 *     heap in .bss) does not fit in the low region, so we link/load it in
 *     the high-RAM window: VA 0x9000_0000_9000_0000 == PA 0x9000_0000.
 *
 * This mirrors the riscv64 linker.ld section layout; only OUTPUT_ARCH,
 * OUTPUT_FORMAT and BASE_ADDRESS differ.
 */

OUTPUT_ARCH(loongarch)
OUTPUT_FORMAT("elf64-loongarch")
ENTRY(_start)

BASE_ADDRESS = 0x9000000090000000;

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
