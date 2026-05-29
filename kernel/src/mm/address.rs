//! Address newtypes and page-number conversions for Sv39.

use core::fmt;

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_BITS: usize = 12;

/// Offset added to a physical address to form a kernel-dereferenceable
/// pointer. riscv64 runs the kernel identity-mapped (PA == VA); on
/// loongarch64 the kernel reaches all of physical memory through the DMW0
/// cached direct-map window based at 0x9000_0000_0000_0000.
#[cfg(target_arch = "riscv64")]
pub const KERNEL_PHYS_OFFSET: usize = 0;
#[cfg(target_arch = "loongarch64")]
pub const KERNEL_PHYS_OFFSET: usize = 0x9000_0000_0000_0000;

/// Number of bits in a Sv39 virtual address (39).
pub const SV39_VA_BITS: usize = 39;
/// Mask covering the 56-bit physical address space.
pub const PA_MASK: usize = (1 << 56) - 1;
/// Mask covering the 39-bit canonical Sv39 VA.
pub const VA_MASK: usize = (1 << SV39_VA_BITS) - 1;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
#[repr(transparent)]
pub struct PhysAddr(pub usize);

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
#[repr(transparent)]
pub struct VirtAddr(pub usize);

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
#[repr(transparent)]
pub struct PhysPageNum(pub usize);

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
#[repr(transparent)]
pub struct VirtPageNum(pub usize);

impl PhysAddr {
    pub fn floor(self) -> PhysPageNum {
        PhysPageNum(self.0 >> PAGE_SIZE_BITS)
    }
    pub fn ceil(self) -> PhysPageNum {
        PhysPageNum((self.0 + PAGE_SIZE - 1) >> PAGE_SIZE_BITS)
    }
    pub fn page_offset(self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }
    pub fn as_mut_ptr<T>(self) -> *mut T {
        (self.0 + KERNEL_PHYS_OFFSET) as *mut T
    }
    /// Reinterpret this physical address as a kernel-accessible pointer.
    /// riscv64 runs identity-mapped (PA == VA); loongarch64 adds the DMW0
    /// window offset (`KERNEL_PHYS_OFFSET`) so the cached direct map is used.
    pub fn kernel_ptr<T>(self) -> *mut T {
        (self.0 + KERNEL_PHYS_OFFSET) as *mut T
    }
}

impl VirtAddr {
    pub fn floor(self) -> VirtPageNum {
        VirtPageNum(self.0 >> PAGE_SIZE_BITS)
    }
    pub fn ceil(self) -> VirtPageNum {
        VirtPageNum((self.0 + PAGE_SIZE - 1) >> PAGE_SIZE_BITS)
    }
    pub fn page_offset(self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }
}

impl PhysPageNum {
    pub fn base(self) -> PhysAddr {
        PhysAddr(self.0 << PAGE_SIZE_BITS)
    }
    /// Slice the page as 512 `usize` entries (used by the page-table walker).
    /// Safe to call only after the page is owned by the caller.
    pub fn as_pte_slice(self) -> &'static mut [usize] {
        let ptr = self.base().kernel_ptr::<usize>();
        unsafe { core::slice::from_raw_parts_mut(ptr, 512) }
    }
    /// Whole-page byte view, e.g. for zeroing.
    pub fn as_byte_slice(self) -> &'static mut [u8] {
        let ptr = self.base().kernel_ptr::<u8>();
        unsafe { core::slice::from_raw_parts_mut(ptr, PAGE_SIZE) }
    }
}

impl VirtPageNum {
    pub fn base(self) -> VirtAddr {
        VirtAddr(self.0 << PAGE_SIZE_BITS)
    }
    /// Returns the three 9-bit VPN indices, MSB first (vpn[2], vpn[1], vpn[0]).
    pub fn indices(self) -> [usize; 3] {
        let mut vpn = self.0;
        let mut out = [0usize; 3];
        for i in 0..3 {
            out[2 - i] = vpn & 0x1ff;
            vpn >>= 9;
        }
        out
    }
}

macro_rules! impl_debug_hex {
    ($t:ty, $name:literal) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($name, "({:#x})"), self.0)
            }
        }
    };
}

impl_debug_hex!(PhysAddr, "PA");
impl_debug_hex!(VirtAddr, "VA");
impl_debug_hex!(PhysPageNum, "PPN");
impl_debug_hex!(VirtPageNum, "VPN");

impl From<usize> for PhysAddr {
    fn from(v: usize) -> Self {
        Self(v & PA_MASK)
    }
}
impl From<usize> for VirtAddr {
    fn from(v: usize) -> Self {
        Self(v)
    }
}
impl From<PhysAddr> for usize {
    fn from(p: PhysAddr) -> Self {
        p.0
    }
}
impl From<VirtAddr> for usize {
    fn from(v: VirtAddr) -> Self {
        v.0
    }
}
