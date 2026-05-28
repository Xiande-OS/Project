use std::env;

fn main() {
    println!("musl hello! argv0 = {}", env::args().next().unwrap_or_default());
    for (i, arg) in env::args().enumerate() {
        println!("  argv[{i}] = {arg}");
    }
    for (k, v) in env::vars() {
        println!("  env: {k}={v}");
    }
    println!("musl hello: bye");
}
