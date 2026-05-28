//! OS-contest test harness driver.
//!
//! The 2026 OS-Kernel contest evaluator boots us with a testsuite EXT4
//! image attached to `virtio-mmio-bus.0`. The image's root has two
//! variant directories — `musl/` and `glibc/` — each containing a
//! flat layout of `*_testcode.sh` scripts plus a `busybox` binary and
//! the ELFs the scripts invoke. Each script is responsible for
//! printing its own `#### OS COMP TEST GROUP START/END <group>-<variant>
//! ####` markers; our job is just to enumerate them and feed each one
//! to a shell.
//!
//! Strategy: mount the EXT4 disk at /mnt, materialise a tiny driver
//! script (/init.sh) that `cd`s into each variant in turn and loops
//! over the testcode scripts, then exec busybox-sh on it. When the
//! shell exits, the scheduler hits "no runnable tasks" and reboots
//! via SBI.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::{self, FileType, Inode};
use crate::println;

const BUSYBOX_PATH: &str = "/bin/busybox";

pub fn prepare_init() -> Option<(Arc<dyn Inode>, Vec<String>)> {
    let mounted = match fs::ext4::mount_at("mnt") {
        Ok(()) => {
            println!("[xiande-os] ext4 mounted at /mnt");
            true
        }
        Err(e) => {
            println!("[xiande-os] ext4 mount failed: {} — empty harness", e);
            false
        }
    };

    // The contest binaries have PT_INTERP pointing at absolute paths
    // under /lib (the riscv64 glibc loader, the musl loader). Make the
    // disk's copies available under /lib so dynamic exec succeeds.
    if mounted {
        bind_loaders();
    }

    let variants: Vec<(String, Vec<String>)> = if mounted {
        enumerate_variants("/mnt")
    } else {
        Vec::new()
    };

    let body = build_driver_script(&variants);
    if let Err(e) = fs::install_file("/", "init.sh", body.as_bytes()) {
        println!("[xiande-os] install_file /init.sh failed: {}", e);
        return None;
    }

    let bb = match fs::lookup_path(fs::root(), BUSYBOX_PATH) {
        Ok(i) => i,
        Err(_) => {
            println!("[xiande-os] {} missing — abort", BUSYBOX_PATH);
            return None;
        }
    };

    let argv: Vec<String> = ["sh", "/init.sh"].iter().map(|s| s.to_string()).collect();
    Some((bb, argv))
}

/// Walk /mnt and pick up the variant directories (musl/glibc) along
/// with their testcode scripts. Falls back to treating /mnt itself as
/// the variant dir when no musl/glibc subdir exists (some test images
/// drop everything at root).
fn enumerate_variants(mount: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let root = match fs::lookup_path(fs::root(), mount) {
        Ok(i) => i,
        Err(_) => return out,
    };
    let entries = root.list().unwrap_or_default();
    let names: Vec<String> = entries.iter().map(|(n, _)| n.clone()).collect();

    let mut has_variant = false;
    for v in ["musl", "glibc"] {
        if names.iter().any(|n| n == v) {
            let dir_path = alloc::format!("{}/{}", mount, v);
            let scripts = list_testcodes(&dir_path);
            if !scripts.is_empty() {
                out.push((dir_path, scripts));
                has_variant = true;
            }
        }
    }

    if !has_variant {
        let scripts = list_testcodes(mount);
        if !scripts.is_empty() {
            out.push((mount.to_string(), scripts));
        }
    }

    out
}

/// Make the dynamic loaders from the testsuite disk accessible at the
/// absolute paths PT_INTERP encodes. Tries each known mapping and just
/// reports failures — missing files mean that variant isn't on the disk.
fn bind_loaders() {
    let mappings: &[(&str, &str)] = &[
        // glibc loader — required by both musl/basic/* and glibc/basic/*.
        ("/mnt/glibc/lib/ld-linux-riscv64-lp64d.so.1", "ld-linux-riscv64-lp64d.so.1"),
        // musl loader (the libc.so on this contest disk IS the loader).
        ("/mnt/musl/libc.so", "ld-musl-riscv64-sf.so.1"),
        ("/mnt/musl/libc.so", "ld-musl-riscv64.so.1"),
    ];
    for (src, dst) in mappings {
        match fs::lookup_path(fs::root(), src) {
            Ok(inode) => {
                if let Err(e) = fs::link_into("/lib", dst, inode) {
                    println!("[xiande-os] link {} -> /lib/{} failed: {}", src, dst, e);
                } else {
                    println!("[xiande-os] /lib/{} -> {}", dst, src);
                }
            }
            Err(_) => {
                // Source missing — that's fine, this variant isn't shipped.
            }
        }
    }
}

fn list_testcodes(dir: &str) -> Vec<String> {
    let inode = match fs::lookup_path(fs::root(), dir) {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };
    if inode.kind() != FileType::Directory {
        return Vec::new();
    }
    let mut entries = inode.list().unwrap_or_default();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
        .into_iter()
        .filter(|(n, _)| n.ends_with("_testcode.sh"))
        .map(|(n, _)| n)
        .collect()
}

fn build_driver_script(variants: &[(String, Vec<String>)]) -> String {
    let mut s = String::from("#!/bin/sh\n");
    if variants.is_empty() {
        s.push_str("echo '#### OS COMP TEST GROUP START basic ####'\n");
        s.push_str("echo '#### OS COMP TEST GROUP END basic ####'\n");
        return s;
    }
    // Sort the per-variant script list so cheap/finite scripts run
    // first and the long-running benchmark ones run last. If a later
    // script hangs we still bank the easy points.
    for (dir, scripts) in variants {
        s.push_str(&alloc::format!("cd {}\n", dir));
        let ordered = order_scripts(scripts);
        for script in ordered {
            // Wrap each script in `busybox timeout` so a single
            // misbehaving testcase can't eat the whole budget.
            // 60s is generous for everything except the explicit
            // benchmarks (cyclictest, lmbench, iozone, iperf, netperf,
            // unixbench, ltp) where we cap tighter.
            let budget = script_budget(&script);
            s.push_str(&alloc::format!(
                "./busybox timeout -s KILL {b} ./busybox sh ./{s}\n",
                b = budget,
                s = script
            ));
        }
    }
    s
}

fn order_scripts(scripts: &[String]) -> Vec<String> {
    // Priority buckets: lower number = run earlier. The benchmark/
    // timing-sensitive groups go last because each has the highest
    // chance of stealing wall-clock time. `basic` is the highest-value
    // and most-likely-to-pass group, so it's first.
    let priority = |name: &str| -> u8 {
        // basic first (highest yield, well-validated). Then the small
        // script-driven ones (lua, busybox). libcbench last among the
        // light ones — its b_malloc_thread_local segfault was killing
        // init mid-stream. Heavy benchmarks at the tail.
        match name {
            n if n.starts_with("basic_") => 0,
            n if n.starts_with("lua_") => 1,
            n if n.starts_with("busybox_") => 2,
            n if n.starts_with("libctest_") => 3,
            n if n.starts_with("libcbench_") => 4,
            n if n.starts_with("cyclictest_") => 5,
            n if n.starts_with("iozone_") => 6,
            n if n.starts_with("lmbench_") => 7,
            n if n.starts_with("iperf_") => 8,
            n if n.starts_with("netperf_") => 9,
            n if n.starts_with("unixbench_") => 10,
            n if n.starts_with("ltp_") => 11,
            _ => 12,
        }
    };
    let mut v: Vec<String> = scripts.iter().cloned().collect();
    v.sort_by(|a, b| priority(a).cmp(&priority(b)).then(a.cmp(b)));
    v
}

fn script_budget(script: &str) -> &'static str {
    match script {
        s if s.starts_with("cyclictest_") => "15",
        s if s.starts_with("iozone_") => "30",
        s if s.starts_with("lmbench_") => "30",
        s if s.starts_with("iperf_") => "20",
        s if s.starts_with("netperf_") => "20",
        s if s.starts_with("unixbench_") => "30",
        s if s.starts_with("ltp_") => "60",
        _ => "30",
    }
}
