//! `cargo run --release --example perf -- <file> [runs]`
//!
//! Times, on a memory-mapped PE file (see `fixtures sparse`), the sequential digest, the
//! sequential digest plus page hashes, and the parallel single pass, for SHA-256 alone and
//! for dual signing (SHA-1 + SHA-256). Prints the best of `runs` (default 3) and the
//! throughput in MB/s (10^6 bytes per second of file), and checks that the results are
//! identical.

use rsigncode::pe::{HashAlgorithm, authenticode_digest, digests, page_hashes};
use std::time::Instant;

fn best<T>(runs: usize, mut f: impl FnMut() -> T) -> (f64, T) {
    let mut best = f64::MAX;
    let mut last = None;
    for _ in 0..runs {
        let start = Instant::now();
        let r = f();
        best = best.min(start.elapsed().as_secs_f64());
        last = Some(r);
    }
    (best, last.expect("at least one run"))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: perf <file> [runs]");
    let runs = args.next().map_or(3, |r| r.parse().expect("runs"));
    let file = std::fs::File::open(path).unwrap();
    // SAFETY: the file is not modified while it is mapped.
    let map = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let mbs = map.len() as f64 / 1e6;
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!(
        "{} MB, {cores} cores, best of {runs}",
        map.len() / 1_000_000
    );

    let sha1 = HashAlgorithm::Sha1;
    let sha256 = HashAlgorithm::Sha256;
    let report = |label: &str, seconds: f64| {
        println!("{label:<48} {seconds:7.3} s {:8.0} MB/s", mbs / seconds);
    };

    // Warm the page cache.
    let _ = authenticode_digest(&map, sha256).unwrap();

    for (name, algorithms) in [
        ("sha256", vec![sha256]),
        ("sha1+sha256", vec![sha1, sha256]),
    ] {
        let (t, seq) = best(runs, || {
            algorithms
                .iter()
                .map(|a| authenticode_digest(&map, *a).unwrap())
                .collect::<Vec<_>>()
        });
        report(&format!("{name}: sequential digest"), t);

        let (t, seq_pages) = best(runs, || {
            let d: Vec<_> = algorithms
                .iter()
                .map(|a| authenticode_digest(&map, *a).unwrap())
                .collect();
            (d, page_hashes(&map, sha256).unwrap())
        });
        report(&format!("{name}: sequential digest + page hashes"), t);
        assert_eq!(seq_pages.0, seq);

        let (t, par) = best(runs, || digests(&map, &algorithms, Some(sha256)).unwrap());
        report(&format!("{name}: parallel single pass (digest + pages)"), t);
        assert_eq!(par.file, seq);
        assert_eq!(par.page_hashes.as_ref(), Some(&seq_pages.1));

        let (t, par) = best(runs, || digests(&map, &algorithms, None).unwrap());
        report(&format!("{name}: parallel digest only"), t);
        assert_eq!(par.file, seq);
    }
    println!("results identical");
}
