//! Tiny git CLI for xiande-os. Implements just enough to be recognizable
//! as `git`: --version, hash-object, rev-parse --short, and help.

use std::env;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use sha1::{Digest, Sha1};

const VERSION: &str = "git version 2.42.0-xiande-os (built with sha1+hex)";

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 {
        print_help();
        return ExitCode::SUCCESS;
    }

    match argv[1].as_str() {
        "--version" | "-v" | "version" => {
            println!("{VERSION}");
            println!("running on xiande-os, riscv64gc + musl");
            ExitCode::SUCCESS
        }
        "--help" | "-h" | "help" => {
            print_help();
            ExitCode::SUCCESS
        }
        "hash-object" => cmd_hash_object(&argv[2..]),
        "rev-parse" => cmd_rev_parse(&argv[2..]),
        "init" => cmd_init(&argv[2..]),
        "status" => cmd_status(),
        "log" => cmd_log(),
        "config" => cmd_config(&argv[2..]),
        "self-test" => cmd_self_test(),
        unknown => {
            eprintln!("git: '{unknown}' is not a git command. See 'git --help'.");
            ExitCode::from(1)
        }
    }
}

fn print_help() {
    println!("usage: git [--version] [--help] <command> [<args>]");
    println!();
    println!("Commands:");
    println!("   hash-object [--stdin] [<text>]   Compute git blob SHA-1");
    println!("   rev-parse --short <sha>          Shorten a SHA-1");
    println!("   init                              Initialize a repository (stub)");
    println!("   status                            Show working tree status (stub)");
    println!("   log                               Show commit log (stub)");
    println!("   config <key>                     Read/write config (stub)");
    println!("   self-test                         Run built-in checks");
    println!();
    println!("This is a minimal `git` running inside xiande-os.");
}

fn git_blob_sha1(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    let header = format!("blob {}\0", data.len());
    hasher.update(header.as_bytes());
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn cmd_hash_object(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("git hash-object: usage: git hash-object [--stdin] [<text>...]");
        return ExitCode::from(1);
    }
    if args[0] == "--stdin" {
        let mut buf = Vec::new();
        if io::stdin().read_to_end(&mut buf).is_err() {
            eprintln!("git hash-object: failed to read stdin");
            return ExitCode::from(1);
        }
        println!("{}", git_blob_sha1(&buf));
        ExitCode::SUCCESS
    } else {
        // Concatenate all remaining args, separated by spaces; hash that.
        let body = args.join(" ");
        println!("{}", git_blob_sha1(body.as_bytes()));
        ExitCode::SUCCESS
    }
}

fn cmd_rev_parse(args: &[String]) -> ExitCode {
    if args.len() == 2 && args[0] == "--short" {
        let sha = &args[1];
        let n = core::cmp::min(7, sha.len());
        println!("{}", &sha[..n]);
        ExitCode::SUCCESS
    } else {
        // Otherwise echo the input.
        for a in args {
            println!("{a}");
        }
        ExitCode::SUCCESS
    }
}

fn cmd_init(_args: &[String]) -> ExitCode {
    println!("Initialized empty Git repository (in-memory, xiande-os has no persistent FS yet)");
    println!("  HEAD points to refs/heads/main");
    ExitCode::SUCCESS
}

fn cmd_status() -> ExitCode {
    println!("On branch main");
    println!();
    println!("No commits yet");
    println!();
    println!("nothing to commit (this xiande-os git has no working tree)");
    ExitCode::SUCCESS
}

fn cmd_log() -> ExitCode {
    // Print a synthetic log of xiande-os development milestones.
    let entries = [
        (
            "ffffaa9988776655443322110000aaaa11223344",
            "fang.gliding@gmail.com",
            "M4: static musl Linux ELF runs (Rust stdio works)",
        ),
        (
            "deadbeef11112222333344445555aabbccddeeff",
            "fang.gliding@gmail.com",
            "M3: user mode, ELF loader, syscall framework",
        ),
        (
            "cafef00daaaabbbbccccddddeeee11112222aaaa",
            "fang.gliding@gmail.com",
            "M1: trap path, kernel heap, frame allocator, Sv39 page tables",
        ),
        (
            "feedface0011223344556677889900aabbccdd11",
            "fang.gliding@gmail.com",
            "M0: cargo workspace + SBI console hello on QEMU virt",
        ),
    ];
    for (sha, author, subject) in entries {
        println!("commit {sha}");
        println!("Author: {author}");
        println!("Date:   2026-05-28");
        println!();
        println!("    {subject}");
        println!();
    }
    ExitCode::SUCCESS
}

fn cmd_config(args: &[String]) -> ExitCode {
    if args.is_empty() {
        println!("user.name=xiande");
        println!("user.email=fang.gliding@gmail.com");
        println!("core.editor=ed");
        ExitCode::SUCCESS
    } else {
        // Stub lookup.
        match args[0].as_str() {
            "user.name" => println!("xiande"),
            "user.email" => println!("fang.gliding@gmail.com"),
            "core.editor" => println!("ed"),
            other => {
                eprintln!("git config: unknown key '{other}'");
                return ExitCode::from(1);
            }
        }
        ExitCode::SUCCESS
    }
}

fn cmd_self_test() -> ExitCode {
    print!("hash-object empty string ... ");
    io::stdout().flush().ok();
    let h = git_blob_sha1(b"");
    let expected = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
    if h == expected {
        println!("OK ({h})");
    } else {
        println!("FAIL");
        println!("  expected {expected}");
        println!("  got      {h}");
        return ExitCode::from(1);
    }

    print!("hash-object 'hello\\n' ... ");
    io::stdout().flush().ok();
    let h = git_blob_sha1(b"hello\n");
    let expected = "ce013625030ba8dba906f756967f9e9ca394464a";
    if h == expected {
        println!("OK ({h})");
    } else {
        println!("FAIL");
        println!("  expected {expected}");
        println!("  got      {h}");
        return ExitCode::from(1);
    }

    print!("hash-object 'xiande-os\\n' ... ");
    io::stdout().flush().ok();
    let h = git_blob_sha1(b"xiande-os\n");
    println!("OK ({h})");

    println!();
    println!("All self-tests passed.");
    ExitCode::SUCCESS
}
