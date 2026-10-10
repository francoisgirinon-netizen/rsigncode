mod common;

use common::{PeBuilder, fixtures, page_fixtures};
use rsigncode::pe::{Error, HashAlgorithm, page_hashes};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn data_file(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Fixture by name: builder fixtures, or the real images of `tests/data` (`tiny32`,
/// `tiny64`).
fn file(name: &str) -> Vec<u8> {
    if let Some((_, d)) = fixtures()
        .into_iter()
        .chain(page_fixtures())
        .find(|(n, _)| *n == name)
    {
        return d;
    }
    data_file(&format!("{name}.efi"))
}

fn algorithm(name: &str) -> HashAlgorithm {
    match name {
        "sha1" => HashAlgorithm::Sha1,
        "sha256" => HashAlgorithm::Sha256,
        other => panic!("{other}"),
    }
}

/// Lines of `tests/data/page_hashes.txt`: (fixture, algorithm, table or "error: ...").
fn oracle() -> Vec<(String, HashAlgorithm, String)> {
    let text = String::from_utf8(data_file("page_hashes.txt")).unwrap();
    text.lines()
        .map(|l| {
            let mut it = l.splitn(3, ' ');
            let name = it.next().unwrap().to_string();
            let alg = algorithm(it.next().unwrap());
            (name, alg, it.next().unwrap().to_string())
        })
        .collect()
}

// Oracle: the page hash tables that `osslsigncode sign -ph -h sha1|sha256` embeds in the
// signature (SpcPeImageData), extracted by `tests/data/page_hashes.sh` into
// `tests/data/page_hashes.txt`. The fixtures cover: page size = SectionAlignment (0x200,
// 0x300, 0x1000, 0x2000), sections spanning several pages with a partial last page,
// section data not starting on a page boundary of the file, empty sections (also last,
// with PointerToRawData = 0), overlay, raw data in reverse order, PE32 and PE32+, and
// real images (tiny32.efi, tiny64.efi: SizeOfHeaders 0x400 in a 0x1000 page).
/// Spec: OSSL-PH-1, OSSL-PH-2, OSSL-PH-3, OSSL-PH-4, OSSL-PH-5, OSSL-PH-6, OSSL-PH-7,
/// OSSL-PH-8 (whole table, byte for byte).
#[test]
fn page_hash_tables_match_osslsigncode() {
    let mut checked = 0;
    for (name, alg, expected) in oracle() {
        if expected.starts_with("error") {
            continue;
        }
        let table = page_hashes(&file(&name), alg).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(hex(&table), expected, "{name} {alg:?}");
        checked += 1;
    }
    assert_eq!(checked, 2 * 17);
}

// Same oracle: osslsigncode refuses these files ("Corrupted page size: 0x00000000",
// "Page size (0x200) is smaller than header size (0x600)" and, for a file without sections,
// "Failed to calculate page hash").
/// Spec: OSSL-PH-9 (SectionAlignment of zero, headers larger than a page, no section).
#[test]
fn files_that_osslsigncode_refuses_are_an_error() {
    let mut refused = 0;
    for (name, alg, expected) in oracle() {
        if !expected.starts_with("error") {
            continue;
        }
        let error = if name == "ph_pe32_no_sections" {
            Error::NoSections
        } else {
            Error::InvalidPageSize
        };
        assert_eq!(page_hashes(&file(&name), alg), Err(error), "{name}");
        refused += 1;
    }
    assert_eq!(refused, 2 * 4);
}

/// Spec: ROBUST-3 (our own limits, the oracle accepts them): a `SectionAlignment` above
/// 1 MiB would make each page cost a long run of zeros to hash, and overlapping sections
/// would make the table larger than the file.
#[test]
fn hostile_alignment_and_overlapping_sections_are_an_error() {
    let d = PeBuilder::new(true)
        .alignment(0x4000_0000)
        .sections(&[0x200])
        .build();
    assert_eq!(
        page_hashes(&d, HashAlgorithm::Sha1),
        Err(Error::InvalidPageSize)
    );
    // Three sections that all cover 0x200..0x800 (the whole file but the headers): each is
    // in bounds, but together they hold three times the file.
    let mut d = PeBuilder::new(true)
        .sections(&[0x600, 0x600, 0x600])
        .build();
    d.truncate(0x800);
    let table = 0x80 + 24 + 240;
    for i in 0..3 {
        let s = table + 40 * i;
        d[s + 16..s + 20].copy_from_slice(&0x600u32.to_le_bytes());
        d[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
    }
    assert_eq!(
        page_hashes(&d, HashAlgorithm::Sha1),
        Err(Error::SectionOutOfBounds)
    );
}

/// Spec: OSSL-PH-1 (entry sizes: 4 + digest length, plus the terminating entry).
#[test]
fn entry_size_follows_the_algorithm() {
    let d = PeBuilder::new(true).sections(&[0x2000]).build();
    // Pages: headers, 2 pages of the section, terminating entry.
    assert_eq!(page_hashes(&d, HashAlgorithm::Sha1).unwrap().len(), 4 * 24);
    assert_eq!(
        page_hashes(&d, HashAlgorithm::Sha256).unwrap().len(),
        4 * 36
    );
}

/// Spec: ROBUST-2 (sections outside the file), ROBUST-3 (never allocate from header values).
/// osslsigncode had a bug of that kind; here the bounds are checked first.
#[test]
fn section_bounds_outside_the_file_are_an_error() {
    // PE32+: section table at 0x80 + 24 + 240, 40-byte entries; SizeOfRawData at +16.
    let table = 0x80 + 24 + 240;
    for (raw_size, raw_offset) in [
        (0xFFFF_FFF0u32, 0x200u32),
        (0x200, 0xFFFF_FFF0),
        (0x1000_0000, 0x200),
        (0x200, 0x1000),
    ] {
        let mut d = PeBuilder::new(true).sections(&[0x200]).build();
        d[table + 16..table + 20].copy_from_slice(&raw_size.to_le_bytes());
        d[table + 20..table + 24].copy_from_slice(&raw_offset.to_le_bytes());
        for a in [HashAlgorithm::Sha1, HashAlgorithm::Sha256] {
            assert_eq!(
                page_hashes(&d, a),
                Err(Error::SectionOutOfBounds),
                "{raw_size:#x}@{raw_offset:#x}"
            );
        }
    }
}

/// Spec: ROBUST-3: the table is never larger than the file allows, even with the smallest
/// accepted SectionAlignment (no page is smaller than the headers).
#[test]
fn table_size_is_bounded_by_the_file() {
    let d = PeBuilder::new(true)
        .alignment(0x200)
        .sections(&[0x4000])
        .build();
    let table = page_hashes(&d, HashAlgorithm::Sha256).unwrap();
    assert!(table.len() <= (d.len() / 0x200 + 2) * 36);
}

/// Spec: ROBUST-1, ROBUST-2 (truncated or corrupted files give an error, no panic).
#[test]
fn malformed_files_never_panic() {
    let d = PeBuilder::new(false).sections(&[0x1400, 0x200]).build();
    for cut in (0..d.len()).step_by(37) {
        let _ = page_hashes(&d[..cut], HashAlgorithm::Sha1);
    }
    let mut x = 0x1234_5678u32;
    for _ in 0..2000 {
        let mut c = d.clone();
        for _ in 0..4 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let at = (x as usize) % 0x300;
            c[at] = (x >> 24) as u8;
        }
        let _ = page_hashes(&c, HashAlgorithm::Sha256);
    }
}
