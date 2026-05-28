    # Trap entry for S-mode.
    #
    # M1: we only trap from S-mode (no user processes yet). The frame
    #     layout matches the user-mode path we'll add in M3, so we don't
    #     have to rewrite the world later.
    #
    # TrapFrame layout (34 * 8 bytes):
    #   [0..30] -> x1..x31  (x0 is hardwired zero, not saved)
    #   [31]    -> sstatus
    #   [32]    -> sepc
    #   [33]    -> reserved / sp-alignment slot

    .section .text.trap, "ax"
    .globl __trap_entry
    .balign 4
__trap_entry:
    # Allocate the TrapFrame on the current stack.
    addi    sp, sp, -34*8

    # Save x1, x3..x31 (skip x0 and x2 = sp; we save the original sp
    # below from a temporary).
    sd      x1,   0*8(sp)
    sd      x3,   2*8(sp)
    sd      x4,   3*8(sp)
    sd      x5,   4*8(sp)
    sd      x6,   5*8(sp)
    sd      x7,   6*8(sp)
    sd      x8,   7*8(sp)
    sd      x9,   8*8(sp)
    sd      x10,  9*8(sp)
    sd      x11, 10*8(sp)
    sd      x12, 11*8(sp)
    sd      x13, 12*8(sp)
    sd      x14, 13*8(sp)
    sd      x15, 14*8(sp)
    sd      x16, 15*8(sp)
    sd      x17, 16*8(sp)
    sd      x18, 17*8(sp)
    sd      x19, 18*8(sp)
    sd      x20, 19*8(sp)
    sd      x21, 20*8(sp)
    sd      x22, 21*8(sp)
    sd      x23, 22*8(sp)
    sd      x24, 23*8(sp)
    sd      x25, 24*8(sp)
    sd      x26, 25*8(sp)
    sd      x27, 26*8(sp)
    sd      x28, 27*8(sp)
    sd      x29, 28*8(sp)
    sd      x30, 29*8(sp)
    sd      x31, 30*8(sp)

    # Original sp = current sp + 34*8.
    addi    t0, sp, 34*8
    sd      t0,   1*8(sp)

    # CSRs.
    csrr    t0, sstatus
    sd      t0, 31*8(sp)
    csrr    t0, sepc
    sd      t0, 32*8(sp)

    # Hand the TrapFrame pointer to Rust.
    mv      a0, sp
    call    rust_trap_handler

    # Restore CSRs.
    ld      t0, 31*8(sp)
    csrw    sstatus, t0
    ld      t0, 32*8(sp)
    csrw    sepc, t0

    # Restore GPRs.
    ld      x1,   0*8(sp)
    ld      x3,   2*8(sp)
    ld      x4,   3*8(sp)
    ld      x5,   4*8(sp)
    ld      x6,   5*8(sp)
    ld      x7,   6*8(sp)
    ld      x8,   7*8(sp)
    ld      x9,   8*8(sp)
    ld      x10,  9*8(sp)
    ld      x11, 10*8(sp)
    ld      x12, 11*8(sp)
    ld      x13, 12*8(sp)
    ld      x14, 13*8(sp)
    ld      x15, 14*8(sp)
    ld      x16, 15*8(sp)
    ld      x17, 16*8(sp)
    ld      x18, 17*8(sp)
    ld      x19, 18*8(sp)
    ld      x20, 19*8(sp)
    ld      x21, 20*8(sp)
    ld      x22, 21*8(sp)
    ld      x23, 22*8(sp)
    ld      x24, 23*8(sp)
    ld      x25, 24*8(sp)
    ld      x26, 25*8(sp)
    ld      x27, 26*8(sp)
    ld      x28, 27*8(sp)
    ld      x29, 28*8(sp)
    ld      x30, 29*8(sp)
    ld      x31, 30*8(sp)

    addi    sp, sp, 34*8
    sret
