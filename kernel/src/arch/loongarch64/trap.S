    # LoongArch64 trap entry (general exceptions) + TLB-refill entry.
    #
    # SAVE0 (CSR 0x30) is the kernel-sp scratch, mirroring riscv64's use of
    # sscratch:
    #   * SAVE0 == 0  -> currently in kernel; sp is already the kernel sp
    #   * SAVE0 != 0  -> currently in user; SAVE0 holds the kernel sp
    #
    # TrapFrame layout (34 * 8 bytes), matching `trap.rs`:
    #   [0..31] -> r0..r31  (r0 saved as 0 for index regularity)
    #   [32]    -> era
    #   [33]    -> prmd

    .section .text.trap, "ax"
    .balign 4096
    .globl __trap_entry
__trap_entry:
    csrwr   $sp, 0x30              # sp <-> SAVE0
    bnez    $sp, 1f               # SAVE0!=0 -> from user (sp now = kernel sp)
    csrwr   $sp, 0x30             # from kernel: undo swap (sp = real sp, SAVE0=0)
1:
    addi.d  $sp, $sp, -34*8        # allocate TrapFrame

    st.d    $ra,  $sp, 1*8
    st.d    $tp,  $sp, 2*8
    st.d    $a0,  $sp, 4*8
    st.d    $a1,  $sp, 5*8
    st.d    $a2,  $sp, 6*8
    st.d    $a3,  $sp, 7*8
    st.d    $a4,  $sp, 8*8
    st.d    $a5,  $sp, 9*8
    st.d    $a6,  $sp, 10*8
    st.d    $a7,  $sp, 11*8
    st.d    $t0,  $sp, 12*8
    st.d    $t1,  $sp, 13*8
    st.d    $t2,  $sp, 14*8
    st.d    $t3,  $sp, 15*8
    st.d    $t4,  $sp, 16*8
    st.d    $t5,  $sp, 17*8
    st.d    $t6,  $sp, 18*8
    st.d    $t7,  $sp, 19*8
    st.d    $t8,  $sp, 20*8
    st.d    $r21, $sp, 21*8
    st.d    $fp,  $sp, 22*8
    st.d    $s0,  $sp, 23*8
    st.d    $s1,  $sp, 24*8
    st.d    $s2,  $sp, 25*8
    st.d    $s3,  $sp, 26*8
    st.d    $s4,  $sp, 27*8
    st.d    $s5,  $sp, 28*8
    st.d    $s6,  $sp, 29*8
    st.d    $s7,  $sp, 30*8
    st.d    $s8,  $sp, 31*8

    csrrd   $t0, 0x6              # ERA
    st.d    $t0, $sp, 32*8
    csrrd   $t0, 0x1             # PRMD
    st.d    $t0, $sp, 33*8

    andi    $t1, $t0, 0x3        # PPLV
    beqz    $t1, 2f              # from kernel
    # from user: original sp in SAVE0; record it, then mark kernel (SAVE0=0)
    csrrd   $t2, 0x30
    st.d    $t2, $sp, 3*8
    move    $t2, $zero
    csrwr   $t2, 0x30
    b       3f
2:
    addi.d  $t2, $sp, 34*8
    st.d    $t2, $sp, 3*8
3:
    move    $a0, $sp             # arg0 = &TrapFrame
    bl      rust_trap_handler
    move    $sp, $a0             # returned TrapFrame pointer
    b       .Ltrap_exit

    .globl __trap_return
__trap_return:
    move    $sp, $a0             # external entry: a0 = TrapFrame to restore

.Ltrap_exit:
    ld.d    $t0, $sp, 33*8       # prmd of frame
    andi    $t1, $t0, 0x3
    beqz    $t1, 4f             # returning to kernel: leave SAVE0 alone
    addi.d  $t2, $sp, 34*8      # returning to user: arm SAVE0 = kernel sp
    csrwr   $t2, 0x30
4:
    csrwr   $t0, 0x1            # PRMD
    ld.d    $t0, $sp, 32*8      # era
    csrwr   $t0, 0x6

    ld.d    $ra,  $sp, 1*8
    ld.d    $tp,  $sp, 2*8
    ld.d    $a0,  $sp, 4*8
    ld.d    $a1,  $sp, 5*8
    ld.d    $a2,  $sp, 6*8
    ld.d    $a3,  $sp, 7*8
    ld.d    $a4,  $sp, 8*8
    ld.d    $a5,  $sp, 9*8
    ld.d    $a6,  $sp, 10*8
    ld.d    $a7,  $sp, 11*8
    ld.d    $t0,  $sp, 12*8
    ld.d    $t1,  $sp, 13*8
    ld.d    $t2,  $sp, 14*8
    ld.d    $t3,  $sp, 15*8
    ld.d    $t4,  $sp, 16*8
    ld.d    $t5,  $sp, 17*8
    ld.d    $t6,  $sp, 18*8
    ld.d    $t7,  $sp, 19*8
    ld.d    $t8,  $sp, 20*8
    ld.d    $r21, $sp, 21*8
    ld.d    $fp,  $sp, 22*8
    ld.d    $s0,  $sp, 23*8
    ld.d    $s1,  $sp, 24*8
    ld.d    $s2,  $sp, 25*8
    ld.d    $s3,  $sp, 26*8
    ld.d    $s4,  $sp, 27*8
    ld.d    $s5,  $sp, 28*8
    ld.d    $s6,  $sp, 29*8
    ld.d    $s7,  $sp, 30*8
    ld.d    $s8,  $sp, 31*8
    ld.d    $sp,  $sp, 3*8       # restore sp last
    ertn

    # ----- TLB refill exception (separate entry at TLBRENTRY) -----------
    #
    # Fires on any TLB miss. Walks the page tables rooted at the PGD CSR
    # (auto low/high-half selected from TLBRBADV) using the hardware walk
    # assists (lddir/ldpte) and refills a TLB entry pair. The page-table
    # node/leaf format must be LoongArch-native for lddir/ldpte to parse
    # it — that MM rework is tracked separately; until then this fires
    # only once user paging is exercised.
    .balign 4096
    .globl __tlb_refill_entry
__tlb_refill_entry:
    csrwr   $t0, 0x8b            # TLBRSAVE = t0
    csrrd   $t0, 0x1b           # PGD root (auto hi/lo from TLBRBADV)
    lddir   $t0, $t0, 3         # top directory -> next level base
    lddir   $t0, $t0, 1         # -> leaf PTE table base
    ldpte   $t0, 0              # even PTE -> TLBRELO0
    ldpte   $t0, 1              # odd PTE  -> TLBRELO1
    tlbfill
    csrrd   $t0, 0x8b           # restore t0
    ertn
