use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn build_user_pkg(cargo: &str, user_dir: &Path, pkg: &str, target: &str, strip: &[&str]) {
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "--release", "--target", target, "-p", pkg])
        .current_dir(user_dir);
    for k in strip {
        cmd.env_remove(k);
    }
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("spawn user cargo for {pkg}: {e}"));
    if !status.success() {
        panic!("cargo build of {pkg} failed: {status}");
    }
}

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

    let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    // Bare-metal hello (M3 / smoke test).
    build_user_pkg(
        &cargo_bin,
        &user_dir,
        "hello",
        "riscv64gc-unknown-none-elf",
        &strip,
    );
    let hello_src = user_dir
        .join("target/riscv64gc-unknown-none-elf/release/hello");
    let hello_dst = out_dir.join("hello.elf");
    std::fs::copy(&hello_src, &hello_dst).expect("copy hello.elf");
    println!("cargo:rustc-env=HELLO_ELF_PATH={}", hello_dst.display());

    // Real musl-linked hello (M4 target).
    build_user_pkg(
        &cargo_bin,
        &user_dir,
        "musl_hello",
        "riscv64gc-unknown-linux-musl",
        &strip,
    );
    let musl_src = user_dir
        .join("target/riscv64gc-unknown-linux-musl/release/musl_hello");
    let musl_dst = out_dir.join("musl_hello.elf");
    std::fs::copy(&musl_src, &musl_dst).expect("copy musl_hello.elf");
    println!("cargo:rustc-env=MUSL_HELLO_ELF_PATH={}", musl_dst.display());
}
