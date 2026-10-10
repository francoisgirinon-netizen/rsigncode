//! `cargo run --release --example oracle -- <dir>`
//!
//! Prints, as JSON, what rsigncode computes for every file of `<dir>` (sorted by name, the
//! key is the file name without extension): size, image checksum and, for SHA-1 and
//! SHA-256, the Authenticode digest and the page hash table (lowercase hex), or the error
//! when there is none. The Windows workflow `signtool-oracle` compares this with the values
//! of SignTool and imagehlp (`ci/signtool_oracle.py compare`).
//!
//! `cargo run --example fixtures -- <dir>` writes the generated fixtures to `<dir>`.

use rsigncode::pe::{HashAlgorithm, authenticode_digest, checksum, page_hashes};
use std::fmt::Write;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A JSON string, or `null`.
fn string(value: Option<String>) -> String {
    match value {
        None => "null".to_string(),
        Some(v) => format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")),
    }
}

/// `"<key>": <hex>` and `"<key>_error": <message>` members for a result.
fn member<E: std::fmt::Display>(key: &str, result: Result<Vec<u8>, E>) -> String {
    let (value, error) = match result {
        Ok(v) => (Some(hex(&v)), None),
        Err(e) => (None, Some(e.to_string())),
    };
    format!(
        "\"{key}\": {}, \"{key}_error\": {}",
        string(value),
        string(error)
    )
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: oracle <dir>");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .expect("directory")
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    let entries: Vec<String> = paths
        .iter()
        .map(|path| {
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            let data = std::fs::read(path).unwrap();
            let sum = checksum(&data);
            let algorithms = [
                ("sha1", HashAlgorithm::Sha1),
                ("sha256", HashAlgorithm::Sha256),
                ("sha384", HashAlgorithm::Sha384),
                ("sha512", HashAlgorithm::Sha512),
            ]
            .map(|(label, a)| {
                    format!(
                        "\"{label}\": {{{}, {}}}",
                        member("digest", authenticode_digest(&data, a)),
                        member("page_hashes", page_hashes(&data, a)),
                    )
                })
                .join(", ");
            let (sum, sum_error) = match sum {
                Ok(v) => (v.to_string(), "null".to_string()),
                Err(e) => ("null".to_string(), string(Some(e.to_string()))),
            };
            format!(
                "  \"{name}\": {{\"size\": {}, \"checksum\": {sum}, \"checksum_error\": {sum_error}, {algorithms}}}",
                data.len()
            )
        })
        .collect();
    println!("{{\n{}\n}}", entries.join(",\n"));
}
