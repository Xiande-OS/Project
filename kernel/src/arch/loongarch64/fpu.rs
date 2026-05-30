//! loongarch64 FP / LSX / LASX context.
//!
//! The kernel is built soft-float and never touches the vector register
//! file, so a task's FP/SIMD state stays live in the hardware from the
//! moment it traps until the CPU is handed to a different task. That makes
//! preemptive context switching responsible for the file: without it, two
//! tasks running vector code (e.g. glibc's LASX `memcpy`/`memset`, or any
//! pthread workload) clobber each other's registers and silently corrupt
//! data.
//!
//! We save the full 256-bit LASX width (which overlays the 128-bit LSX and
//! 64-bit FP registers) plus the eight condition flags and FCSR, so the
//! save/restore is correct regardless of which extension the task uses.

use core::arch::global_asm;

/// Saved vector unit state. `vregs` holds `$xr0..$xr31` (32 bytes each);
/// `fcc` holds the eight 1-bit condition flags; `fcsr` is the control word.
/// `#[repr(C, align(32))]` keeps `xvst`/`xvld` on their natural alignment.
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct FpContext {
    pub vregs: [u64; 128], // 32 * 256 bits
    pub fcc: [u8; 8],
    pub fcsr: u32,
    _pad: u32,
}

impl FpContext {
    pub const fn new() -> Self {
        Self {
            vregs: [0; 128],
            fcc: [0; 8],
            fcsr: 0,
            _pad: 0,
        }
    }
}

extern "C" {
    fn __fp_save(ctx: *mut FpContext);
    fn __fp_restore(ctx: *const FpContext);
}

/// Save the live vector register file into `ctx`.
///
/// # Safety
/// `ctx` must point to a valid, writable `FpContext`. The caller must hold
/// the CPU (no other hart races the register file).
#[inline]
pub unsafe fn save(ctx: *mut FpContext) {
    __fp_save(ctx);
}

/// Load `ctx` into the vector register file.
///
/// # Safety
/// `ctx` must point to a valid `FpContext`.
#[inline]
pub unsafe fn restore(ctx: *const FpContext) {
    __fp_restore(ctx);
}

// $a0 = context pointer. Leaf routines: only the caller-saved $t0 scratch
// and the (caller-clobbered) vector file are touched, so no prologue is
// needed. Offsets match the FpContext layout above: vregs at 0 (32B each),
// fcc bytes at 1024, fcsr word at 1032.
global_asm!(
    r#"
    .section .text
    .globl __fp_save
    .align 4
__fp_save:
    xvst $xr0,  $a0, 0
    xvst $xr1,  $a0, 32
    xvst $xr2,  $a0, 64
    xvst $xr3,  $a0, 96
    xvst $xr4,  $a0, 128
    xvst $xr5,  $a0, 160
    xvst $xr6,  $a0, 192
    xvst $xr7,  $a0, 224
    xvst $xr8,  $a0, 256
    xvst $xr9,  $a0, 288
    xvst $xr10, $a0, 320
    xvst $xr11, $a0, 352
    xvst $xr12, $a0, 384
    xvst $xr13, $a0, 416
    xvst $xr14, $a0, 448
    xvst $xr15, $a0, 480
    xvst $xr16, $a0, 512
    xvst $xr17, $a0, 544
    xvst $xr18, $a0, 576
    xvst $xr19, $a0, 608
    xvst $xr20, $a0, 640
    xvst $xr21, $a0, 672
    xvst $xr22, $a0, 704
    xvst $xr23, $a0, 736
    xvst $xr24, $a0, 768
    xvst $xr25, $a0, 800
    xvst $xr26, $a0, 832
    xvst $xr27, $a0, 864
    xvst $xr28, $a0, 896
    xvst $xr29, $a0, 928
    xvst $xr30, $a0, 960
    xvst $xr31, $a0, 992
    movcf2gr $t0, $fcc0
    st.b  $t0, $a0, 1024
    movcf2gr $t0, $fcc1
    st.b  $t0, $a0, 1025
    movcf2gr $t0, $fcc2
    st.b  $t0, $a0, 1026
    movcf2gr $t0, $fcc3
    st.b  $t0, $a0, 1027
    movcf2gr $t0, $fcc4
    st.b  $t0, $a0, 1028
    movcf2gr $t0, $fcc5
    st.b  $t0, $a0, 1029
    movcf2gr $t0, $fcc6
    st.b  $t0, $a0, 1030
    movcf2gr $t0, $fcc7
    st.b  $t0, $a0, 1031
    movfcsr2gr $t0, $fcsr0
    st.w  $t0, $a0, 1032
    ret

    .globl __fp_restore
    .align 4
__fp_restore:
    xvld $xr0,  $a0, 0
    xvld $xr1,  $a0, 32
    xvld $xr2,  $a0, 64
    xvld $xr3,  $a0, 96
    xvld $xr4,  $a0, 128
    xvld $xr5,  $a0, 160
    xvld $xr6,  $a0, 192
    xvld $xr7,  $a0, 224
    xvld $xr8,  $a0, 256
    xvld $xr9,  $a0, 288
    xvld $xr10, $a0, 320
    xvld $xr11, $a0, 352
    xvld $xr12, $a0, 384
    xvld $xr13, $a0, 416
    xvld $xr14, $a0, 448
    xvld $xr15, $a0, 480
    xvld $xr16, $a0, 512
    xvld $xr17, $a0, 544
    xvld $xr18, $a0, 576
    xvld $xr19, $a0, 608
    xvld $xr20, $a0, 640
    xvld $xr21, $a0, 672
    xvld $xr22, $a0, 704
    xvld $xr23, $a0, 736
    xvld $xr24, $a0, 768
    xvld $xr25, $a0, 800
    xvld $xr26, $a0, 832
    xvld $xr27, $a0, 864
    xvld $xr28, $a0, 896
    xvld $xr29, $a0, 928
    xvld $xr30, $a0, 960
    xvld $xr31, $a0, 992
    ld.bu $t0, $a0, 1024
    movgr2cf $fcc0, $t0
    ld.bu $t0, $a0, 1025
    movgr2cf $fcc1, $t0
    ld.bu $t0, $a0, 1026
    movgr2cf $fcc2, $t0
    ld.bu $t0, $a0, 1027
    movgr2cf $fcc3, $t0
    ld.bu $t0, $a0, 1028
    movgr2cf $fcc4, $t0
    ld.bu $t0, $a0, 1029
    movgr2cf $fcc5, $t0
    ld.bu $t0, $a0, 1030
    movgr2cf $fcc6, $t0
    ld.bu $t0, $a0, 1031
    movgr2cf $fcc7, $t0
    ld.w  $t0, $a0, 1032
    movgr2fcsr $fcsr0, $t0
    ret
"#
);
