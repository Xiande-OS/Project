/* Minimal vDSO linker script (riscv64). Single LOAD segment, with a
 * SHT_PROGBITS .eh_frame and PT_GNU_EH_FRAME so the unwinder + glibc can
 * locate the CFI. Modeled on arch/riscv/kernel/vdso/vdso.lds.S. */
OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)

SECTIONS
{
	. = SIZEOF_HEADERS;

	.hash		: { *(.hash) }			:text
	.gnu.hash	: { *(.gnu.hash) }
	.dynsym		: { *(.dynsym) }
	.dynstr		: { *(.dynstr) }
	.gnu.version	: { *(.gnu.version) }
	.gnu.version_d	: { *(.gnu.version_d) }
	.gnu.version_r	: { *(.gnu.version_r) }

	.dynamic	: { *(.dynamic) }		:text :dynamic

	.rodata		: { *(.rodata*) }		:text

	.text		: { *(.text*) }			:text

	.eh_frame_hdr	: { *(.eh_frame_hdr) }		:text :eh_frame_hdr
	.eh_frame	: { KEEP (*(.eh_frame)) }	:text
}

PHDRS
{
	text		PT_LOAD		FLAGS(5) FILEHDR PHDRS; /* PF_R|PF_X */
	dynamic		PT_DYNAMIC	FLAGS(4);		/* PF_R */
	eh_frame_hdr	PT_GNU_EH_FRAME;
}

VERSION
{
	LINUX_4.15 {
	global:
		__vdso_rt_sigreturn;
	local: *;
	};
}
