#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod arch;
#[macro_use]
mod console;
mod drivers;
mod fs;
mod loader;
mod mm;
mod sync;
mod syscall;
mod task;

use core::panic::PanicInfo;

#[repr(C, align(8))]
struct AlignedElf<T: ?Sized>(T);

static HELLO_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("HELLO_ELF_PATH")));
static MUSL_HELLO_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("MUSL_HELLO_ELF_PATH")));
static GIT_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("GIT_ELF_PATH")));
static REAL_GIT_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("REAL_GIT_ELF_PATH")));
static BUSYBOX_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("BUSYBOX_ELF_PATH")));
static DYN_HELLO_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("DYN_HELLO_ELF_PATH")));
static LD_MUSL_ALIGNED: &AlignedElf<[u8]> =
    &AlignedElf(*include_bytes!(env!("LD_MUSL_PATH")));

fn hello_elf() -> &'static [u8] {
    &HELLO_ALIGNED.0
}
fn musl_hello_elf() -> &'static [u8] {
    &MUSL_HELLO_ALIGNED.0
}
fn git_elf() -> &'static [u8] {
    &GIT_ALIGNED.0
}
fn real_git_elf() -> &'static [u8] {
    &REAL_GIT_ALIGNED.0
}
fn busybox_elf() -> &'static [u8] {
    &BUSYBOX_ALIGNED.0
}
fn dyn_hello_elf() -> &'static [u8] {
    &DYN_HELLO_ALIGNED.0
}
fn ld_musl_blob() -> &'static [u8] {
    &LD_MUSL_ALIGNED.0
}

#[no_mangle]
pub extern "C" fn kmain(hartid: usize, dtb_pa: usize) -> ! {
    println!("xiande-os booting on hart {}", hartid);
    println!("  dtb @ {:#x}", dtb_pa);

    mm::init();
    arch::riscv64::trap::init();
    fs::init();

    // Drop runnable binaries into /bin so execve can resolve them.
    let bb = fs::install_file("/bin", "busybox", busybox_elf()).unwrap();
    for applet in [
        "sh", "ash", "ls", "cat", "echo", "mkdir", "rm", "rmdir", "mv", "cp",
        "true", "false", "env", "pwd", "wc", "grep", "head", "tail", "sort",
        "uniq", "tr", "find", "touch", "test", "[", "[[", "stat",
    ] {
        fs::link_into("/bin", applet, bb.clone()).unwrap();
    }
    fs::install_file("/bin", "git", real_git_elf()).unwrap();
    fs::install_file("/bin", "dyn_hello", dyn_hello_elf()).unwrap();
    // Install the dynamic linker so PT_INTERP="/lib/ld-musl-riscv64.so.1" works.
    if let Some(td) = fs::tmpfs::downcast_dir(&fs::root()) {
        let lib_dir = fs::tmpfs::TmpfsDir::new_root();
        td.place_inode("lib", lib_dir as alloc::sync::Arc<dyn fs::Inode>).ok();
    }
    fs::install_file("/lib", "ld-musl-riscv64.so.1", ld_musl_blob()).unwrap();
    println!("[ok] heap + frame allocator + trap vector + vfs + /bin + /lib");

    if let Some(_blk) = drivers::virtio_blk::init() {
        match fs::fat32::mount("/mnt") {
            Ok(()) => println!("[ok] virtio-blk + FAT32 mounted at /mnt"),
            Err(e) => println!("[fat32] mount failed: {}", e),
        }
    } else {
        println!("[virtio-blk] no block device detected");
    }
    if option_env!("SYSTRACE").is_some() {
        syscall::set_syscall_trace(true);
    }

    let (name, elf, argv) = if cfg!(feature = "bare_hello") {
        ("hello", hello_elf(), alloc::vec!["hello"])
    } else if cfg!(feature = "musl_hello") {
        ("musl_hello", musl_hello_elf(), alloc::vec!["musl_hello"])
    } else if cfg!(feature = "rust_git") {
        let cmd = option_env!("GIT_CMD").unwrap_or("self-test");
        let split: alloc::vec::Vec<&str> = cmd.split_whitespace().collect();
        let mut a = alloc::vec!["git"];
        a.extend_from_slice(&split);
        ("git", git_elf(), a)
    } else if cfg!(feature = "shell") {
        let cmd = option_env!("SHELL_CMD").unwrap_or("echo hello from busybox");
        let applet = option_env!("APPLET").unwrap_or("sh");
        let mut a = alloc::vec![applet];
        if applet == "sh" || applet == "ash" {
            a.push("-c");
            a.push(cmd);
        } else {
            for arg in cmd.split_whitespace() {
                a.push(arg);
            }
        }
        (applet, busybox_elf(), a)
    } else if cfg!(feature = "dyn_hello") {
        ("dyn_hello", dyn_hello_elf(), alloc::vec!["dyn_hello", "alpha", "beta"])
    } else {
        let cmd = option_env!("GIT_CMD").unwrap_or("--version");
        let split: alloc::vec::Vec<&str> = cmd.split_whitespace().collect();
        let mut a = alloc::vec!["git"];
        a.extend_from_slice(&split);
        ("real_git", real_git_elf(), a)
    };
    println!("[user] loading {} ({} bytes)", name, elf.len());
    println!("[user] argv = {:?}", argv);
    let task = task::create_task_from_elf(elf, &argv, &["PATH=/bin", "HOME=/", "TERM=dumb"]);
    println!("[user] task installed, entering user mode...");
    task::run_user_loop(&task);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[kernel panic] {}", info);
    sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
    loop {
        unsafe { core::arch::asm!("wfi") };
    }
}

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("alloc error: {:?}", layout);
}
