    # Trap entry for both S-mode (kernel) and U-mode (user) traps.
    #
    # Convention:
    #   * sscratch == 0      -> in S-mode (kernel)
    #   * sscratch != 0      -> in U-mode; sscratch holds the kernel sp
    #                           to switch to on trap
    #
    # TrapFrame layout (34 * 8 bytes):
    #   [0..30] -> x1..x31  (x0 is hardwired zero, not saved)
    #   [31]    -> sstatus
    #   [32]    -> sepc
    #   [33]    -> reserved / 16-byte alignment pad

    .section .text.trap, "ax"
    .globl __trap_entry
    .balign 4
__trap_entry:
    csrrw   sp, sscratch, sp
    bnez    sp, 1f
    # From S-mode: undo the swap so sp goes back to its original value.
    csrrw   sp, sscratch, sp
1:
    addi    sp, sp, -34*8

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

    csrr    t0, sstatus
    sd      t0, 31*8(sp)
    csrr    t0, sepc
    sd      t0, 32*8(sp)

    # SPP bit 8: 1 = from S-mode, 0 = from U-mode.
    andi    t1, t0, 0x100
    bnez    t1, 2f
    # From U-mode: original sp lives in sscratch.
    csrr    t2, sscratch
    sd      t2,  1*8(sp)
    csrw    sscratch, zero
    j       3f
2:
    # From S-mode: original sp = (current sp + 34*8).
    addi    t2, sp, 34*8
    sd      t2,  1*8(sp)
3:
    mv      a0, sp
    call    rust_trap_handler

    # sp is callee-saved per RISC-V ABI, so it still points at the
    # TrapFrame. Continue into the shared exit path.
    j       .Ltrap_exit

    .globl __trap_return
__trap_return:
    # External entry: a0 = TrapFrame pointer to restore from.
    mv      sp, a0

.Ltrap_exit:
    ld      t0, 31*8(sp)
    csrw    sstatus, t0
    ld      t1, 32*8(sp)
    csrw    sepc, t1

    # If returning to U-mode (SPP == 0), arm sscratch with kernel sp.
    andi    t1, t0, 0x100
    bnez    t1, 4f
    addi    t1, sp, 34*8
    csrw    sscratch, t1
4:
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

    ld      x2,   1*8(sp)
    sret
