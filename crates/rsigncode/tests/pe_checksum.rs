mod common;

use common::{PeBuilder, fixtures};
use rsigncode::pe::{Error, checksum};

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

// Oracle: `osslsigncode verify -in <file>` prints "PE checksum", the value it stored when
// signing (SignTool for tiny64.signed.efi).
#[test]
fn checksum_of_signed_files_matches_the_tools() {
    assert_eq!(checksum(&data("pe32_extra_3.signed.exe")), Ok(0xAD78));
    assert_eq!(checksum(&data("pe64_aligned.signed.exe")), Ok(0xC95C));
    assert_eq!(checksum(&data("tiny64.signed.efi")), Ok(0x7DA8));
}

// Oracle: `osslsigncode remove-signature` on pe32_extra_3.signed.exe recomputes the checksum
// of the unsigned (padded) file and writes it in the header.
#[test]
fn checksum_of_unsigned_file_matches_osslsigncode() {
    assert_eq!(
        checksum(&data("pe32_extra_3.unsigned-by-ossl.exe")),
        Ok(0x157C)
    );
}

#[test]
fn checksum_ignores_the_checksum_field() {
    let a = PeBuilder::new(false).build();
    let mut b = a.clone();
    b[0xD8..0xDC].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(checksum(&a), checksum(&b));
    assert!(checksum(&a).is_ok());
}

// Hand computation: all the words are summed, so changing one byte of an unaligned file
// changes the result by the expected amount.
#[test]
fn checksum_of_odd_length_file_counts_the_last_byte_as_low_byte() {
    let a = fixtures()
        .into_iter()
        .find(|(n, _)| *n == "pe32_extra_1")
        .unwrap()
        .1;
    let mut b = a.clone();
    *b.last_mut().unwrap() ^= 1;
    let (ca, cb) = (checksum(&a).unwrap(), checksum(&b).unwrap());
    // The last byte is the low byte of its word: a one bit change moves the sum by 1,
    // unless it carries, hence the tolerance of one.
    assert_eq!(ca.abs_diff(cb), 1);
}

#[test]
fn checksum_of_malformed_file_is_an_error() {
    assert_eq!(checksum(&[]), Err(Error::Truncated));
    assert_eq!(checksum(b"MZ"), Err(Error::Truncated));
}
