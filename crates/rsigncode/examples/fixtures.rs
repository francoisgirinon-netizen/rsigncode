//! Test fixture generator, to compare rsigncode with other tools.
//!
//! - `cargo run --example fixtures -- <dir>`: writes the named fixtures to `<dir>`.
//! - `cargo run --example fixtures -- sparse <file> <MiB>`: writes a sparse PE32+ file whose
//!   single section is a hole of about `<MiB>` MiB (for benchmarks).

use std::io::Write;

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, path, mib] if cmd == "sparse" => {
            let size = mib.parse::<usize>().expect("MiB") * 1024 * 1024;
            let builder = common::PeBuilder::new(true).sections(&[size]);
            let (headers, total) = builder.build_sparse();
            let mut f = std::fs::File::create(path).unwrap();
            f.write_all(&headers).unwrap();
            f.set_len(total).unwrap();
        }
        [dir] => {
            for (name, data) in common::fixtures()
                .into_iter()
                .chain(common::page_fixtures())
                .chain(common::signtool_fixtures())
            {
                std::fs::write(format!("{dir}/{name}.exe"), data).unwrap();
            }
        }
        _ => panic!("usage: fixtures <dir> | fixtures sparse <file> <MiB>"),
    }
}
