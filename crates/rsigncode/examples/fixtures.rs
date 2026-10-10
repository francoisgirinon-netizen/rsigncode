//! Writes the named test fixtures to a directory, to compare them with other tools:
//! `cargo run --example fixtures -- <dir>`.

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: fixtures <dir>");
    for (name, data) in common::fixtures() {
        std::fs::write(format!("{dir}/{name}.exe"), data).unwrap();
    }
}
