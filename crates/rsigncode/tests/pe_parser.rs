mod common;

use common::PeBuilder;
use rsigncode::pe::PeFile;

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Spec: PECOFF-1, PECOFF-2, PECOFF-3, PECOFF-4, PECOFF-5, PECOFF-6, PECOFF-7.
/// Offsets follow from the layout of the PE format: e_lfanew 0x80, "PE\0\0" + COFF header
/// (24 bytes), CheckSum at +64 of the optional header, data directories at +96 (PE32) or
/// +112 (PE32+), Certificate Table is entry 4.
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

/// Spec: PECOFF-2, PECOFF-3, PECOFF-4, PECOFF-5 (PE32+ layout).
#[test]
fn offsets_of_pe32_plus() {
    let d = PeBuilder::new(true).build();
    let pe = PeFile::parse(&d).unwrap();
    assert!(pe.is_pe32_plus);
    assert_eq!(pe.checksum_offset, 0x98 + 64);
    assert_eq!(pe.certificate_entry_offset, 0x98 + 112 + 32);
}

/// Spec: PECOFF-1, PECOFF-2, PECOFF-3, PECOFF-4, PECOFF-5, PECOFF-6 on real images (tools'
/// output, not our builder): offsets recomputed in the test from e_lfanew.
#[test]
fn offsets_of_real_images() {
    for (file, plus) in [("tiny32.efi", false), ("tiny64.efi", true)] {
        let d = data(file);
        let pe = PeFile::parse(&d).unwrap();
        let e_lfanew = u32::from_le_bytes(d[0x3c..0x40].try_into().unwrap()) as usize;
        let opt = e_lfanew + 24;
        let dirs = opt + if plus { 112 } else { 96 };
        assert_eq!(pe.is_pe32_plus, plus, "{file}");
        assert_eq!(pe.checksum_offset, opt + 64, "{file}");
        assert_eq!(pe.certificate_entry_offset, dirs + 4 * 8, "{file}");
        let soh = u32::from_le_bytes(d[opt + 60..opt + 64].try_into().unwrap()) as usize;
        assert_eq!(pe.size_of_headers, soh, "{file}");
    }
}

/// Spec: PECOFF-5 (the entry holds a file offset, not an RVA), PECOFF-8 (the table starts
/// on a quadword boundary and the bytes before it, back to the end of the data, are zero),
/// SIGNTOOL-1. Oracle: files signed by osslsigncode and SignTool.
#[test]
fn certificate_table_of_signed_files() {
    // (file, size of the unsigned file)
    for (file, unsigned_len) in [
        ("pe64_aligned.signed.exe", 0x800usize),
        ("pe32_extra_3.signed.exe", 0x403),
        ("tiny64.signed.efi", 2048),
    ] {
        let d = data(file);
        let pe = PeFile::parse(&d).unwrap();
        let table = pe.certificate_table.unwrap();
        assert_eq!(table.start % 8, 0, "{file}");
        assert_eq!(table.end, d.len(), "{file}");
        assert_eq!(table.start, unsigned_len.next_multiple_of(8), "{file}");
        assert!(
            d[unsigned_len..table.start].iter().all(|&b| b == 0),
            "{file}"
        );
        // The first field of the WIN_CERTIFICATE is its length, which includes the header.
        let dw_length = u32::from_le_bytes(d[table.start..table.start + 4].try_into().unwrap());
        assert!(dw_length as usize <= table.len(), "{file}");
    }
}
