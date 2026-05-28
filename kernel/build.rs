use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../user/hello/src/main.rs");
    println!("cargo:rerun-if-changed=../user/hello/linker.ld");
    println!("cargo:rerun-if-changed=../user/Cargo.toml");
    println!("cargo:rerun-if-changed=../user/hello/Cargo.toml");
    println!("cargo:rerun-if-changed=../user/.cargo/config.toml");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().to_path_buf();
    let user_dir = workspace_root.join("user");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Linker script for the kernel itself (absolute path so rust-lld
    // can find it regardless of cwd at link time).
    let linker_script = manifest_dir.join("linker.ld");
    println!(
        "cargo:rustc-link-arg=-T{}",
        linker_script.display()
    );
    println!("cargo:rerun-if-changed=linker.ld");

    let mut cmd = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.args(["build", "--release", "-p", "hello"])
        .current_dir(&user_dir);

    // Cargo passes its config (rustflags, target, etc.) to subprocesses via
    // env vars that take priority over the user/.cargo/config.toml we want.
    // Strip them so the user build sees a clean slate.
    let strip = [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_TARGET_RISCV64GC_UNKNOWN_NONE_ELF_RUSTFLAGS",
        "CARGO_TARGET_RISCV64GC_UNKNOWN_NONE_ELF_LINKER",
    ];
    for k in &strip {
        cmd.env_remove(k);
    }

    let status = cmd.status().expect("spawn user cargo build");
    if !status.success() {
        panic!("user cargo build failed: {status}");
    }

    let built = user_dir
        .join("target")
        .join("riscv64gc-unknown-none-elf")
        .join("release")
        .join("hello");
    if !built.exists() {
        panic!("user binary not found at {}", built.display());
    }
    let dest = out_dir.join("hello.elf");
    std::fs::copy(&built, &dest).expect("copy hello.elf");
    println!("cargo:rustc-env=HELLO_ELF_PATH={}", dest.display());
}
