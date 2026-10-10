//! `cargo run --release --example digest -- <file> [sha1|sha256|sha384|sha512]`
//!
//! Prints the Authenticode digest of a memory-mapped PE file.

use rsigncode::pe::{HashAlgorithm, authenticode_digest};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: digest <file> [algorithm]");
    let algorithm = match args.next().as_deref().unwrap_or("sha256") {
        "sha1" => HashAlgorithm::Sha1,
        "sha256" => HashAlgorithm::Sha256,
        "sha384" => HashAlgorithm::Sha384,
        "sha512" => HashAlgorithm::Sha512,
        other => panic!("unknown algorithm {other}"),
    };
    let file = std::fs::File::open(path).unwrap();
    // SAFETY: the file is not modified while it is mapped.
    let map = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let digest = authenticode_digest(&map, algorithm).unwrap();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
