use std::env;
use std::path::PathBuf;

fn copy_or_stub(src: PathBuf, dst: PathBuf, env_var: &str) {
    if src.exists() {
        std::fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!("copy {} -> {}: {e}", src.display(), dst.display())
        });
        println!("cargo:rerun-if-changed={}", src.display());
    } else {
        // No prebuilt available (e.g. contest mode, evaluator stripped binaries).
        // Emit an empty placeholder so include_bytes! still compiles.
        std::fs::write(&dst, []).unwrap();
    }
    println!("cargo:rustc-env={}={}", env_var, dst.display());
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().to_path_buf();
    let user_dir = workspace_root.join("user");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Linker script for the kernel itself (absolute path so rust-lld can
    // find it regardless of cwd at link time). Pick the per-architecture
    // script based on the target cargo is building for.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let linker_name = if target_arch == "loongarch64" {
        "linker-la.ld"
    } else {
        "linker.ld"
    };
    let linker_script = manifest_dir.join(linker_name);
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-la.ld");

    // For each embedded user-mode binary, prefer a checked-in prebuilt.
    // The contest harness rejects on-line dependency downloads, so we
    // never spawn nested `cargo build` invocations for the user-land
    // workspace from here — that wiring is now in xtask.
    //
    // The prebuilt user binaries are RISC-V ELFs; for a loongarch64 kernel
    // the embedded `hello` is the freestanding LA test program (built from
    // user/hello-la.S) so the LA port can exercise user mode without a disk.
    let hello_src = if target_arch == "loongarch64" {
        "hello-la.elf"
    } else {
        "hello.elf"
    };
    copy_or_stub(
        user_dir.join(hello_src),
        out_dir.join("hello.elf"),
        "HELLO_ELF_PATH",
    );
    copy_or_stub(
        user_dir.join("musl_hello.elf"),
        out_dir.join("musl_hello.elf"),
        "MUSL_HELLO_ELF_PATH",
    );
    copy_or_stub(
        user_dir.join("git.elf"),
        out_dir.join("git.elf"),
        "GIT_ELF_PATH",
    );
    copy_or_stub(
        user_dir.join("real_git.elf"),
        out_dir.join("real_git.elf"),
        "REAL_GIT_ELF_PATH",
    );
    copy_or_stub(
        user_dir.join("busybox.elf"),
        out_dir.join("busybox.elf"),
        "BUSYBOX_ELF_PATH",
    );
    copy_or_stub(
        user_dir.join("dyn_hello.elf"),
        out_dir.join("dyn_hello.elf"),
        "DYN_HELLO_ELF_PATH",
    );
    copy_or_stub(
        user_dir.join("ld-musl-riscv64.so.1"),
        out_dir.join("ld-musl-riscv64.so.1"),
        "LD_MUSL_PATH",
    );
    // Freestanding LoongArch "hello" used by the `la_hello` boot feature to
    // smoke-test user paging + the first syscall end-to-end on LA. Empty
    // placeholder on RV (or if the prebuilt is absent).
    copy_or_stub(
        user_dir.join("la_hello.elf"),
        out_dir.join("la_hello.elf"),
        "LA_HELLO_ELF_PATH",
    );

    // In-kernel symbol table ("ksyms"). `ksyms.rs` does
    // `include_bytes!(env!("KSYMS_BIN_PATH"))`; we point it straight at
    // `ksyms-<arch>.bin` at the workspace root. A post-link Makefile step
    // (`ksyms-embed`) regenerates that file from the just-linked kernel and
    // rebuilds — rustc tracks include_bytes! inputs in its dep-info, so the
    // second `cargo build` recompiles `ksyms.rs` with the real table and
    // relinks (two-pass). The blob lives in .rodata (after .text in the link),
    // so embedding it never moves a .text address, and the addresses a pass-1
    // blob records stay correct for the pass-2 kernel.
    //
    // A normal one-pass build (or a direct `cargo build`) just sees the empty
    // placeholder created here — `ksyms::resolve` returns None and the kernel
    // prints raw addresses exactly as before. So this is purely additive and
    // can never break the build.
    let ksyms = workspace_root.join(format!("ksyms-{target_arch}.bin"));
    if !ksyms.exists() {
        let _ = std::fs::write(&ksyms, []);
    }
    // Re-run this script (and recompile ksyms.rs) whenever the blob is
    // (re)generated or removed — this recreates the placeholder on a rebuild
    // where the file was deleted but the cached build script would otherwise be
    // skipped, and drives the pass-2 pickup of a freshly generated table.
    println!("cargo:rerun-if-changed={}", ksyms.display());
    println!("cargo:rustc-env=KSYMS_BIN_PATH={}", ksyms.display());
}
