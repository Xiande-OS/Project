//! In-kernel symbol resolution ("ksyms"). A post-link build step embeds a
//! compact `{sorted addrs, names}` blob (see `scripts/gen_ksyms.py`) so the
//! kernel can turn a fault/panic PC into `function+offset` *by itself* —
//! crucial for the contest, where the grader's rustc (and thus .text layout)
//! may differ from any local build, so a bare `era=0x...` won't addr2line.
//!
//! Fail-safe: if the blob is absent/empty (the placeholder a normal one-pass
//! build embeds), every lookup just returns `None` and callers fall back to
//! printing the raw address — exactly the pre-ksyms behaviour. So a failed or
//! skipped symbol-generation step can never break the build or the kernel.

/// The embedded blob. `build.rs` points `KSYMS_BIN_PATH` at the generated file
/// (or an empty placeholder). Layout (all little-endian):
///   u32 magic=0x4B53594D, u32 count,
///   u64 addr[count] (ascending), u32 name_off[count],
///   u32 strtab_len, u8 strtab[strtab_len] (NUL-terminated names).
static BLOB: &[u8] = include_bytes!(env!("KSYMS_BIN_PATH"));

/// Fetch the blob through an optimisation barrier. CRITICAL for the two-pass
/// embed: pass 1 links with an EMPTY placeholder blob. If the optimiser could
/// see that (a known-empty const), it would prove `table()` returns None,
/// const-fold `available()`/`resolve()` to nothing, and dead-code-eliminate
/// every `if ksyms::available()` block — shrinking `.text`. Pass 2 (real,
/// non-empty blob) keeps that code, so `.text` would be LARGER and every
/// address the pass-1 blob recorded would be wrong (observed: kmain off by
/// 0x2a0). `black_box` makes the blob's content AND length opaque, so both
/// passes generate byte-identical code and the recorded addresses stay valid.
#[inline(never)]
fn blob() -> &'static [u8] {
    // Load the slice (data pointer AND length) from BLOB's address at runtime,
    // through an opaque pointer, so neither field is materialized as a
    // value-dependent immediate. `black_box(BLOB)` alone still let the length
    // (0 in pass 1 vs the real size in pass 2) be const-loaded, which shifted
    // this function's code — and thus every later .text address — by a few
    // bytes. Reading the fat pointer from memory makes both passes byte-identical.
    unsafe { *core::hint::black_box(core::ptr::addr_of!(BLOB)) }
}

const MAGIC: u32 = 0x4B53_594D;

#[inline]
fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
#[inline]
fn rd_u64(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

struct Table {
    count: usize,
    addrs_off: usize,   // u64[count]
    names_off: usize,   // u32[count]
    strtab_off: usize,
    strtab_len: usize,
}

fn table() -> Option<Table> {
    let b = blob();
    if rd_u32(b, 0)? != MAGIC {
        return None;
    }
    let count = rd_u32(b, 4)? as usize;
    if count == 0 {
        return None;
    }
    let addrs_off = 8;
    let names_off = addrs_off + count * 8;
    let strtab_len_off = names_off + count * 4;
    let strtab_len = rd_u32(b, strtab_len_off)? as usize;
    let strtab_off = strtab_len_off + 4;
    // Bounds-check the whole blob so a truncated one degrades to None.
    if strtab_off.checked_add(strtab_len)? > b.len() {
        return None;
    }
    Some(Table { count, addrs_off, names_off, strtab_off, strtab_len })
}

/// Resolve `addr` to the nearest enclosing function symbol, returning its name
/// and the byte offset of `addr` from the symbol's start.
pub fn resolve(addr: usize) -> Option<(&'static str, usize)> {
    let t = table()?;
    let b = blob();
    let addr = addr as u64;
    let at = |i: usize| rd_u64(b, t.addrs_off + i * 8).unwrap_or(u64::MAX);
    if addr < at(0) {
        return None;
    }
    // Largest index whose addr <= query.
    let (mut lo, mut hi) = (0usize, t.count - 1);
    while lo < hi {
        let mid = (lo + hi + 1) / 2;
        if at(mid) <= addr {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    let base = at(lo);
    let name_off = rd_u32(b, t.names_off + lo * 4)? as usize;
    let s = t.strtab_off + name_off;
    let strtab = b.get(t.strtab_off..t.strtab_off + t.strtab_len)?;
    let rel = name_off;
    let end = strtab.get(rel..)?.iter().position(|&c| c == 0)? + rel;
    let name = core::str::from_utf8(b.get(s..t.strtab_off + end)?).ok()?;
    Some((name, (addr - base) as usize))
}

/// True if a real symbol table is embedded (i.e. not the empty placeholder).
pub fn available() -> bool {
    table().is_some()
}

/// Print `  <addr>  <name>+<off>` (or just the address if unresolved). Used by
/// the panic/fault paths to annotate a PC or return address.
pub fn print_frame(label: &str, addr: usize) {
    match resolve(addr) {
        Some((name, off)) => crate::println!("  {label} {addr:#018x}  {name}+{off:#x}"),
        None => crate::println!("  {label} {addr:#018x}  ??"),
    }
}
