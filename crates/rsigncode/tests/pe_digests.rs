mod common;

use common::{PeBuilder, fixtures, page_fixtures, pattern};
use rsigncode::pe::{Error, HashAlgorithm, authenticode_digest, digests, page_hashes};

const ALL: [HashAlgorithm; 4] = [
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
];

/// The page hash algorithms the format has (SHA-1 and SHA-256).
const PAGE: [HashAlgorithm; 2] = [HashAlgorithm::Sha1, HashAlgorithm::Sha256];

fn assert_same_as_sequential(name: &str, data: &[u8]) {
    for page in PAGE {
        // Dual signing (SHA-1 + SHA-256), and all four algorithms in one call.
        for algorithms in [
            &ALL[..],
            &[HashAlgorithm::Sha1, HashAlgorithm::Sha256],
            &[HashAlgorithm::Sha512],
        ] {
            let got =
                digests(data, algorithms, Some(page)).unwrap_or_else(|e| panic!("{name}: {e}"));
            let file: Vec<_> = algorithms
                .iter()
                .map(|a| authenticode_digest(data, *a).unwrap())
                .collect();
            assert_eq!(got.file, file, "{name} file digests");
            assert_eq!(
                got.page_hashes,
                Some(page_hashes(data, page).unwrap()),
                "{name} page hashes"
            );
        }
    }
}

/// Spec: PAR-1 (byte-identical to the sequential functions), PAR-2 (order of the results).
/// Fixtures with several pages, empty sections, reversed sections and real images.
#[test]
fn single_pass_equals_the_sequential_functions() {
    let mut n = 0;
    for (name, data) in fixtures().into_iter().chain(page_fixtures()) {
        // Files that have no page hashes are tested below.
        if page_hashes(&data, HashAlgorithm::Sha1).is_err() {
            continue;
        }
        assert_same_as_sequential(name, &data);
        n += 1;
    }
    assert!(n >= 20, "{n}");
    for name in ["tiny32.efi", "tiny64.efi"] {
        let d = std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        assert_same_as_sequential(name, &d);
    }
}

/// Spec: PAR-1 on a file with many pages, so that the page hashes are really split between
/// threads (1 MiB of random data = 256 pages of 4 KiB, in two sections).
#[test]
fn single_pass_equals_the_sequential_functions_on_many_pages() {
    let mut d = PeBuilder::new(true)
        .sections(&[0x10_0000, 0x3_5000, 0x200])
        .overlay_len(777)
        .build();
    // Random content rather than the builder's pattern, which repeats nothing but is cheap.
    let noise = pattern(d.len() - 0x400, 0x5EED);
    d[0x400..].copy_from_slice(&noise);
    assert_same_as_sequential("many pages", &d);
}

/// Spec: PAR-3 (the page hashes are optional; no algorithm is allowed too).
#[test]
fn page_hashes_and_file_digests_are_optional() {
    let d = PeBuilder::new(false).sections(&[0x1400]).build();
    let r = digests(&d, &[HashAlgorithm::Sha256], None).unwrap();
    assert_eq!(
        r.file,
        vec![authenticode_digest(&d, HashAlgorithm::Sha256).unwrap()]
    );
    assert_eq!(r.page_hashes, None);
    let r = digests(&d, &[], Some(HashAlgorithm::Sha1)).unwrap();
    assert!(r.file.is_empty());
    assert_eq!(
        r.page_hashes,
        Some(page_hashes(&d, HashAlgorithm::Sha1).unwrap())
    );
}

/// Spec: PAR-4 (errors are those of the sequential functions: a file whose page hashes
/// cannot be computed still gets its digest when page hashes are not requested).
#[test]
fn errors_are_reported_like_the_sequential_functions() {
    let d = PeBuilder::new(true).alignment(0).sections(&[0x200]).build();
    assert_eq!(
        digests(&d, &[HashAlgorithm::Sha256], Some(HashAlgorithm::Sha256)),
        Err(Error::InvalidPageSize)
    );
    assert!(digests(&d, &[HashAlgorithm::Sha256], None).is_ok());
    // Section outside the file.
    let mut d = PeBuilder::new(true).sections(&[0x200]).build();
    let table = 0x80 + 24 + 240;
    d[table + 16..table + 20].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert_eq!(
        digests(&d, &[HashAlgorithm::Sha1], None),
        Err(Error::SectionOutOfBounds)
    );
    assert_eq!(
        digests(&d, &[], Some(HashAlgorithm::Sha1)),
        Err(Error::SectionOutOfBounds)
    );
    assert_eq!(digests(&[1, 2, 3], &[], None), Err(Error::BadDosSignature));
    assert_eq!(digests(b"MZ", &[], None), Err(Error::Truncated));
}
