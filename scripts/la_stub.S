        .section .text
        .globl _start
_start:
        # Magic byte: SLP_TYP=5 (bits 4:2) | SLP_EN (bit 5) = 0x34
        addi.d  $r6, $r0, 0x34

        # Try the GED SLEEP_CTL via every plausible address form so we don't
        # depend on what state QEMU LA virt boots us in (DMW0/DMW1/DA).
        # Correct GED REG base in QEMU LA virt:
        #   VIRT_GED_REG_ADDR = VIRT_GED_EVT_ADDR + 4 + 24 = 0x100E001C
        # SLEEP_CTL = REG_BASE + 0, so address 0x100E001C.

        # --- 1) physical-ish (DA mode would treat as physical)
        lu12i.w $r5, 0x100E0
        ori     $r5, $r5, 0x01C
        st.b    $r6, $r5, 0

        # --- 2) via DMW1 vseg 0x9 (cacheable map QEMU LA usually presets)
        lu12i.w $r5, 0x100E0
        ori     $r5, $r5, 0x01C
        lu52i.d $r5, $r5, -1792              # bits 0x900 -> 0x9000000000000000
        st.b    $r6, $r5, 0

        # --- 3) via DMW0 vseg 0x8 (uncached). Also set up DMW0+DMW1+CRMD.PG
        # in case neither was preset.
        lu12i.w $r4, 0
        ori     $r4, $r4, 0x11               # MAT=uncached + PLV0 enable
        lu52i.d $r4, $r4, -2048              # bits 0x800
        csrwr   $r4, 0x180                   # CSR_DMW0 = 0x8000000000000011

        lu12i.w $r4, 0
        ori     $r4, $r4, 0x11
        lu52i.d $r4, $r4, -1792              # bits 0x900
        csrwr   $r4, 0x181                   # CSR_DMW1 = 0x9000000000000011

        addi.d  $r4, $r0, 0x10               # CRMD: PG=1, DA=0, PLV=0, IE=0
        csrwr   $r4, 0x0                     # CSR_CRMD

        lu12i.w $r5, 0x100E0
        ori     $r5, $r5, 0x01C
        lu52i.d $r5, $r5, -2048              # 0x80000000100E001C (uncached MMIO)
        st.b    $r6, $r5, 0

        # If nothing exited, halt forever (don't burn 100% CPU)
1:      idle 0
        b 1b
