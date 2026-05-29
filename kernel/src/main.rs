#![no_std]
#![no_main]
// No unstable features used. Since Rust 1.68 the default allocation-error
// handler already panics, so we don't need a custom #[alloc_error_handler]
// — and dropping it lets us build on stable Rust (so the grader doesn't
// have to download a pinned nightly toolchain).

extern crate alloc;

mod arch;
#[macro_use]
mod console;
mod contest_runner;
mod drivers;
mod fs;
mod loader;
mod mm;
mod net;
mod signal;
mod sync;
mod syscall;
mod task;
mod vdso;

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
    // Parse the embedded vDSO once (panics early on any layout problem).
    vdso::init();
    fs::init();

    // Drop runnable binaries into /bin so execve can resolve them.
    let bb = fs::install_file("/bin", "busybox", busybox_elf()).unwrap();
    // Some testcode scripts use `#!/busybox sh` shebangs (lua's test.sh
    // in particular). Plant a /busybox node so the shebang resolves.
    fs::link_into("/", "busybox", bb.clone()).unwrap();
    for applet in [
        "sh", "ash", "ls", "cat", "echo", "mkdir", "rm", "rmdir", "mv", "cp",
        "true", "false", "env", "pwd", "wc", "grep", "head", "tail", "sort",
        "uniq", "tr", "find", "touch", "test", "[", "[[", "stat",
        "sleep", "kill",
    ] {
        fs::link_into("/bin", applet, bb.clone()).unwrap();
    }
    let git_inode = fs::install_file("/bin", "git", real_git_elf()).unwrap();
    // Real git is a multicall binary: when invoked as `git-<sub>` it
    // dispatches to that sub-builtin via argv[0]. fetch-pack forks off
    // `git-index-pack`, clone forks off helpers, etc. — link the
    // common ones in.
    for applet in [
        "git-index-pack", "git-unpack-objects", "git-pack-objects",
        "git-upload-pack", "git-receive-pack", "git-fetch-pack",
        "git-send-pack", "git-http-backend", "git-http-fetch",
        "git-http-push", "git-remote-http", "git-remote-https",
        "git-remote-ftp", "git-remote-ftps", "git-shell", "git-clone",
        "git-init", "git-init-db", "git-fetch", "git-pull", "git-push",
        "git-checkout", "git-add", "git-commit", "git-status", "git-log",
        "git-show", "git-diff", "git-merge", "git-config", "git-rev-list",
        "git-rev-parse", "git-cat-file", "git-hash-object", "git-update-ref",
        "git-update-index", "git-write-tree", "git-read-tree", "git-ls-files",
        "git-ls-tree", "git-ls-remote", "git-symbolic-ref", "git-pack-refs",
    ] {
        fs::link_into("/bin", applet, git_inode.clone()).unwrap();
    }
    fs::install_file("/bin", "dyn_hello", dyn_hello_elf()).unwrap();
    // Install the dynamic linker so PT_INTERP="/lib/ld-musl-riscv64.so.1" works.
    // Also mount tmpfs at /tmp so tmpfile()/mkstemp from libc-test work.
    if let Some(td) = fs::tmpfs::downcast_dir(&fs::root()) {
        let lib_dir = fs::tmpfs::TmpfsDir::new_root();
        td.place_inode("lib", lib_dir as alloc::sync::Arc<dyn fs::Inode>).ok();
        let tmp_dir = fs::tmpfs::TmpfsDir::new_root();
        td.place_inode("tmp", tmp_dir as alloc::sync::Arc<dyn fs::Inode>).ok();
    }
    fs::install_file("/lib", "ld-musl-riscv64.so.1", ld_musl_blob()).unwrap();
    // POSIX shared-memory mount point at /dev/shm.
    if let Ok(dev_dir) = fs::root().lookup("dev") {
        if let Some(d) = fs::tmpfs::downcast_dir(&dev_dir) {
            let shm = fs::tmpfs::TmpfsDir::new_root();
            d.place_inode("shm", shm as alloc::sync::Arc<dyn fs::Inode>).ok();
            // busybox hwclock probes /dev/misc/rtc (and /dev/rtc) — provide a
            // stub character device so open() succeeds. The default ioctl
            // path returns 0, which is enough for hwclock to exit cleanly.
            let misc = fs::tmpfs::TmpfsDir::new_root();
            misc.create_special("rtc", fs::devfs::DevKind::Null).ok();
            misc.create_special("rtc0", fs::devfs::DevKind::Null).ok();
            d.place_inode("misc", misc as alloc::sync::Arc<dyn fs::Inode>).ok();
            d.create_special("rtc", fs::devfs::DevKind::Null).ok();
            d.create_special("rtc0", fs::devfs::DevKind::Null).ok();
        }
    }
    println!("[ok] heap + frame allocator + trap vector + vfs + /bin + /lib + /dev/shm");

    if let Some(_blk) = drivers::virtio_blk::init() {
        // Contest mode mounts EXT4 inside contest_runner — skip FAT32
        // probe here. Dev builds still get a FAT32 attempt for the
        // local disk.img convenience.
        if !cfg!(feature = "contest") {
            match fs::fat32::mount("/mnt") {
                Ok(()) => println!("[ok] virtio-blk + FAT32 mounted at /mnt"),
                Err(e) => println!("[fat32] mount failed: {}", e),
            }
        }
    } else {
        println!("[virtio-blk] no block device detected");
    }
    if let Some(_n) = drivers::virtio_net::init() {
        fs::socket::init();
    } else {
        println!("[virtio-net] no network device detected");
    }
    if option_env!("SYSTRACE").is_some() {
        syscall::set_syscall_trace(true);
    }
    if option_env!("NETTRACE").is_some() {
        syscall::set_nettrace(true);
    }

    // Contest mode: mount the testsuite EXT4 disk, build a driver
    // script that loops over every `*_testcode.sh`, and hand it to
    // busybox sh. When sh exits the scheduler shuts the machine down
    // via SBI on its own.
    if cfg!(feature = "contest") || option_env!("XIANDE_CONTEST").is_some() {
        if let Some((bb_inode, argv)) = contest_runner::prepare_init() {
            let size = bb_inode.size() as usize;
            let mut elf_bytes = alloc::vec![0u8; size];
            if let Err(e) = bb_inode.read_at(0, &mut elf_bytes) {
                panic!("contest: read busybox: {:?}", e);
            }
            let argv_refs: alloc::vec::Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
            let task = task::create_task_from_elf_with_path(
                &elf_bytes,
                &argv_refs,
                &["PATH=/bin:/mnt:/mnt/musl:/mnt/glibc", "HOME=/", "TERM=dumb", "PWD=/"],
                "/bin/busybox",
            );
            drop(elf_bytes);
            println!("[user] contest init: busybox sh /init.sh");
            task::run_user_loop(&task);
        }
        // Fall through to a hard shutdown if prepare_init failed.
        println!("[xiande-os] contest prep failed — shutting down");
        arch::shutdown();
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
    } else if cfg!(feature = "console") {
        // Interactive shell. busybox ash with no args == read-eval-print
        // loop on stdin. Compile-time SHELL_CMD can preload an `-i` script.
        ("sh", busybox_elf(), alloc::vec!["sh", "-i"])
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
    // Best-effort exe path for /proc/<pid>/exe. busybox applets all resolve
    // to /bin/busybox.
    let exe_path: &str = match name {
        "real_git" => "/bin/git",
        "git" => "/bin/git",
        "hello" => "/bin/hello",
        "musl_hello" => "/bin/musl_hello",
        "dyn_hello" => "/bin/dyn_hello",
        _ => "/bin/busybox",
    };
    let task = task::create_task_from_elf_with_path(
        elf,
        &argv,
        &["PATH=/bin", "HOME=/", "TERM=dumb"],
        exe_path,
    );
    println!("[user] task installed, entering user mode...");
    task::run_user_loop(&task);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[kernel panic] {}", info);
    arch::shutdown_failure();
}

