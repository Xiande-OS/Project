//! xtask: project automation runner.
//!
//! Subcommands:
//!   build          — cross-compile the kernel
//!   qemu           — build then boot in QEMU virt
//!   qemu --gdb     — same, but pause for a gdb connection on :1234

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const KERNEL_TARGET: &str = "riscv64gc-unknown-none-elf";
const KERNEL_PKG: &str = "kernel";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    let rest = &args[2.min(args.len())..];

    let res = match cmd {
        "build" => cmd_build(rest),
        "qemu" => cmd_qemu(rest),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("xtask: unknown subcommand `{other}`");
            print_help();
            return ExitCode::from(2);
        }
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    eprintln!(
        "xtask — xiande-os automation\n\
         \n\
         USAGE:\n    cargo xtask <subcommand> [flags]\n\
         \n\
         SUBCOMMANDS:\n\
             build         Cross-compile the kernel\n\
             qemu          Build kernel and run under QEMU virt\n\
         \n\
         QEMU FLAGS:\n\
             --release     Build in release mode (default)\n\
             --debug       Build in dev mode\n\
             --gdb         Pause QEMU at startup and wait for gdb on :1234\n\
             --smp <N>     Use N harts (default 1 for M0)\n"
    );
}

#[derive(Clone, Copy)]
enum Profile {
    Release,
    Dev,
}

impl Profile {
    fn dir(self) -> &'static str {
        match self {
            Profile::Release => "release",
            Profile::Dev => "debug",
        }
    }
    fn cargo_flag(self) -> Option<&'static str> {
        match self {
            Profile::Release => Some("--release"),
            Profile::Dev => None,
        }
    }
}

fn cmd_build(args: &[String]) -> Result<(), String> {
    let profile = parse_profile(args);
    build_kernel(profile)?;
    let elf = kernel_elf_path(profile);
    println!("kernel ELF: {}", elf.display());
    Ok(())
}

fn parse_profile(args: &[String]) -> Profile {
    if args.iter().any(|a| a == "--debug") {
        Profile::Dev
    } else {
        Profile::Release
    }
}

fn build_kernel(profile: Profile) -> Result<(), String> {
    let workspace = workspace_root();
    let kernel_dir = workspace.join("kernel");
    let mut cmd = Command::new(cargo());
    // Run cargo from inside kernel/ so that kernel/.cargo/config.toml is
    // picked up (its rustflags reference kernel/linker.ld relatively).
    cmd.current_dir(&kernel_dir)
        .arg("build")
        .arg("--target")
        .arg(KERNEL_TARGET);
    if let Some(flag) = profile.cargo_flag() {
        cmd.arg(flag);
    }
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("cargo build failed to spawn: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build exited with status {status}"));
    }
    Ok(())
}

fn cmd_qemu(args: &[String]) -> Result<(), String> {
    let profile = parse_profile(args);
    let gdb = args.iter().any(|a| a == "--gdb");
    let smp = parse_smp(args)?;
    build_kernel(profile)?;
    let elf = kernel_elf_path(profile);
    if !elf.exists() {
        return Err(format!("kernel ELF not found at {}", elf.display()));
    }

    let mut qemu = Command::new("qemu-system-riscv64");
    qemu.args([
        "-machine",
        "virt",
        "-nographic",
        "-bios",
        "default",
        "-kernel",
    ])
    .arg(&elf)
    .args(["-smp", &smp.to_string()])
    .args(["-m", "1G"]);

    if gdb {
        qemu.args(["-s", "-S"]);
        eprintln!("qemu: paused for gdb on :1234 (use `target remote :1234`)");
    }

    eprintln!("qemu: launching {}", elf.display());
    let status = qemu
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::inherit())
        .status()
        .map_err(|e| format!("qemu failed to spawn: {e}"))?;

    if !status.success() {
        // QEMU exits non-zero when the guest issues system_reset; that's normal.
        // Treat any non-signal exit as success here (the guest output already shown).
        eprintln!("qemu exited with {status}");
    }
    Ok(())
}

fn parse_smp(args: &[String]) -> Result<u32, String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--smp" {
            let v = it
                .next()
                .ok_or_else(|| "--smp requires a value".to_string())?;
            return v
                .parse::<u32>()
                .map_err(|e| format!("invalid --smp value `{v}`: {e}"));
        }
    }
    Ok(1)
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at xtask/. Workspace root is the parent.
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| here.to_path_buf())
}

fn cargo() -> String {
    env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn kernel_elf_path(profile: Profile) -> PathBuf {
    workspace_root()
        .join("target")
        .join(KERNEL_TARGET)
        .join(profile.dir())
        .join(KERNEL_PKG)
}
