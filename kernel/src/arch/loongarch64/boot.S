    # xiande-os boot entry — LoongArch64 (single-core bring-up).
    #
    # QEMU `virt` direct-boots the ELF: it loads the image into RAM and
    # enters at `_start` with the direct-map windows + paged mode already
    # configured. We re-establish DMW0/DMW1 and CRMD defensively (writing
    # CSRs touches no memory, so it is safe in either DA or paged mode),
    # set up the boot stack, clear .bss, enable the FPU, and tail-call the
    # Rust `kmain`.
    #
    #   DMW0: VA 0x9000_0000_0000_0000 -> PA 0, coherent cached  (kernel text/data)
    #   DMW1: VA 0x8000_0000_0000_0000 -> PA 0, uncached         (MMIO)

    .section .text.entry, "ax"
    .globl _start
    .align 4
_start:
    # DMW0 = 0x9 << 60 | MAT(coherent cached, bit4) | PLV0 enable (bit0)
    li.d        $t0, 0x9000000000000011
    csrwr       $t0, 0x180
    # DMW1 = 0x8 << 60 | MAT(uncached, 0) | PLV0 enable (bit0)
    li.d        $t0, 0x8000000000000001
    csrwr       $t0, 0x181

    # CRMD: PG=1(bit4), DATF=01(bits6:5 cached), DATM=01(bits8:7 cached),
    # PLV=0, IE=0, DA=0.
    li.d        $t0, 0x000000b0
    csrwr       $t0, 0x0

    # Boot stack (top; grows down). PC-relative so it works regardless of
    # whether we entered at the high-half VA or a direct PA.
    la.local    $sp, __boot_stack_top

    # Zero .bss before any Rust runs.
    la.local    $t0, __bss_start
    la.local    $t1, __bss_end
1:
    bgeu        $t0, $t1, 2f
    st.d        $zero, $t0, 0
    addi.d      $t0, $t0, 8
    b           1b
2:
    # EUEN: enable FP (FPE), 128-bit vector (SXE/LSX) and 256-bit vector
    # (ASXE/LASX) for userspace. The LoongArch C library resolves its
    # memcpy/memset/str* ifuncs to LSX/LASX variants, and code built for
    # -march=la464 emits vector ops inline; with only FPE set, those
    # instructions raise an SXD/ASXD ("vector unit disabled") exception on
    # first use and the process dies. Enable all three eagerly at boot (no
    # lazy/trap-driven switching), the same way FPE already was.
    li.w        $t0, 0x7
    csrwr       $t0, 0x2

    # kmain(hartid = 0, dtb = 0). QEMU enters with a0..a3 carrying efi-style
    # scalars (not a DTB pointer), so we don't forward them; the kernel finds
    # the flattened device tree by scanning low RAM in mm::init instead.
    move        $a0, $zero
    move        $a1, $zero
    bl          kmain

    # kmain never returns; park if it does.
3:
    idle        0
    b           3b
