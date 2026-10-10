mod common;

use common::PeBuilder;
use rsigncode::pe::PeFile;

// Offsets follow from the layout of the PE format: e_lfanew 0x80, "PE\0\0" + COFF header
// (24 bytes), CheckSum at +64 of the optional header, data directories at +96 (PE32) or
// +112 (PE32+), Certificate Table is entry 4.
#[test]
fn offsets_of_pe32() {
    let d = PeBuilder::new(false).sections(&[0x200, 0x400]).build();
    let pe = PeFile::parse(&d).unwrap();
    assert!(!pe.is_pe32_plus);
    assert_eq!(pe.checksum_offset, 0x98 + 64);
    assert_eq!(pe.certificate_entry_offset, 0x98 + 96 + 32);
    assert_eq!(pe.size_of_headers, 0x200);
    assert_eq!(pe.sections.len(), 2);
    assert_eq!(pe.sections[1].raw_offset, 0x400);
    assert_eq!(pe.sections[1].raw_size, 0x400);
    assert_eq!(pe.certificate_table, None);
}

#[test]
fn offsets_of_pe32_plus() {
    let d = PeBuilder::new(true).build();
    let pe = PeFile::parse(&d).unwrap();
    assert!(pe.is_pe32_plus);
    assert_eq!(pe.checksum_offset, 0x98 + 64);
    assert_eq!(pe.certificate_entry_offset, 0x98 + 112 + 32);
}

// Oracle: osslsigncode verify reports one signature; the certificate table of its output is
// the tail of the file, after the 8-byte padded content.
#[test]
fn certificate_table_of_a_signed_file() {
    let path = format!(
        "{}/tests/data/pe64_aligned.signed.exe",
        env!("CARGO_MANIFEST_DIR")
    );
    let d = std::fs::read(path).unwrap();
    let pe = PeFile::parse(&d).unwrap();
    let table = pe.certificate_table.unwrap();
    assert_eq!(table.start % 8, 0);
    assert_eq!(table.end, d.len());
}
