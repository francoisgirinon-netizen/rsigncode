//! Benchmarks of the PE hashing, run by CodSpeed in CI (it counts instructions, so the
//! result does not depend on the noise of a shared runner) and by `cargo bench` locally.
//!
//! The file is small (4 x 512 KiB sections) to keep the instrumented run short. For
//! throughput on a large file, use `examples/perf.rs`.

#[path = "../tests/common/mod.rs"]
mod common;

use codspeed_criterion_compat::{Criterion, black_box, criterion_group, criterion_main};
use common::PeBuilder;
use rsigncode::pe::{HashAlgorithm, authenticode_digest, checksum, digests, page_hashes};

fn pe(c: &mut Criterion) {
    let file = PeBuilder::new(true).sections(&[512 * 1024; 4]).build();

    for (name, algorithm) in [
        ("sha1", HashAlgorithm::Sha1),
        ("sha256", HashAlgorithm::Sha256),
        ("sha384", HashAlgorithm::Sha384),
        ("sha512", HashAlgorithm::Sha512),
    ] {
        c.bench_function(&format!("authenticode_digest/{name}"), |b| {
            b.iter(|| authenticode_digest(black_box(&file), algorithm).unwrap());
        });
    }

    c.bench_function("page_hashes/sha256", |b| {
        b.iter(|| page_hashes(black_box(&file), HashAlgorithm::Sha256).unwrap());
    });
    c.bench_function("checksum", |b| {
        b.iter(|| checksum(black_box(&file)).unwrap());
    });
    c.bench_function("digests/sha1+sha256+pages", |b| {
        b.iter(|| {
            digests(
                black_box(&file),
                &[HashAlgorithm::Sha1, HashAlgorithm::Sha256],
                Some(HashAlgorithm::Sha256),
            )
            .unwrap()
        });
    });
}

criterion_group!(benches, pe);
criterion_main!(benches);
