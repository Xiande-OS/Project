    # xiande-os boot entry (M0: single-hart bring-up)
    #
    # OpenSBI hands off:
    #   a0 = hartid
    #   a1 = device tree blob (DTB) physical address
    #
    # We set up the boot stack and jump to Rust `kmain` with the
    # arguments preserved. SMP secondary-hart entry will land in
    # a separate symbol (M2) so we don't bake "always hart 0" into
    # the ABI.

    .section .text.entry, "ax"
    .globl _start
    .align 4
_start:
    # Park any unexpected secondary harts; M0 is single-hart only.
    # OpenSBI's fw_jump only brings up hart 0 by default, but be defensive.
    bnez    a0, .Lpark_secondary

    # Set up the boot stack (defined in linker.ld). Stack grows down.
    la      sp, __boot_stack_top

    # Clear the .bss section before any Rust code runs.
    la      t0, __bss_start
    la      t1, __bss_end
1:
    bgeu    t0, t1, 2f
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       1b
2:

    # Tail-call into Rust. a0 (hartid) and a1 (dtb) are untouched.
    call    kmain

    # kmain should never return. If it does, fall through to park.
.Lpark_secondary:
    wfi
    j       .Lpark_secondary
