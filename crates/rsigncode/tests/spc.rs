use rsigncode::pe::{HashAlgorithm, authenticode_digest};
use rsigncode::spc::{Error, PeImageFlags, indirect_data_content, pe_image_data};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn data_file(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// `<<<Obsolete>>>` as the `file` link: `[0] { [2] { [0] BMPString } }`.
const OBSOLETE_LINK: &str = "a020a21e801c003c003c003c004f00620073006f006c006500740065003e003e003e";

/// `SpcIndirectDataContent` of `tiny64.signed.efi` (SignTool) and `pe32_extra_3.signed.exe`
/// (osslsigncode), cut out of their PKCS#7 (`openssl asn1parse -strparse`).
const SIGNTOOL_SPC: &str = "30683033060a2b06010401823702010f3025030100a020a21e801c003c003c003c004f00620073006f006c006500740065003e003e003e3031300d060960864801650304020105000420a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae";
const OSSL_SPC: &str = "30693034060a2b06010401823702010f302603020780a020a21e801c003c003c003c004f00620073006f006c006500740065003e003e003e3031300d060960864801650304020105000420e57d1456bb4d5e609491ec90fc623e52c91074d7b68155a36572c2034093c1b7";

/// Spec: SPC-1
/// `SpcPeImageData` = flags + obsolete file link, as found in the `SpcIndirectDataContent`
/// of `tiny64.signed.efi` (SignTool, no flag) and `pe32_extra_3.signed.exe` (osslsigncode,
/// `includeResources`).
#[test]
fn pe_image_data_matches_real_signatures() {
    assert_eq!(
        hex(&pe_image_data(PeImageFlags::NONE)),
        format!("3025030100{OBSOLETE_LINK}")
    );
    assert_eq!(
        hex(&pe_image_data(PeImageFlags::INCLUDE_RESOURCES)),
        format!("302603020780{OBSOLETE_LINK}")
    );
}

/// Spec: SPC-2
/// `SpcIndirectDataContent` rebuilt from the digest of the file itself: byte for byte what
/// SignTool and osslsigncode embedded.
#[test]
fn indirect_data_content_matches_real_signatures() {
    for (file, flags, expected) in [
        ("tiny64.signed.efi", PeImageFlags::NONE, SIGNTOOL_SPC),
        (
            "pe32_extra_3.signed.exe",
            PeImageFlags::INCLUDE_RESOURCES,
            OSSL_SPC,
        ),
    ] {
        let data = data_file(file);
        let digest = authenticode_digest(&data, HashAlgorithm::Sha256).unwrap();
        let spc =
            indirect_data_content(&pe_image_data(flags), HashAlgorithm::Sha256, &digest).unwrap();
        assert_eq!(hex(&spc), expected, "{file}");
    }
}

/// Spec: SPC-3
/// The algorithm identifier is the standard one with NULL parameters, for each digest.
#[test]
fn indirect_data_content_algorithm_identifiers() {
    for (algorithm, oid) in [
        (HashAlgorithm::Sha1, "06052b0e03021a"),
        (HashAlgorithm::Sha256, "0609608648016503040201"),
        (HashAlgorithm::Sha384, "0609608648016503040202"),
        (HashAlgorithm::Sha512, "0609608648016503040203"),
    ] {
        let digest = vec![0xab; algorithm.output_len()];
        let spc = hex(&indirect_data_content(&[0x30, 0], algorithm, &digest).unwrap());
        assert!(spc.contains(&format!("{oid}0500")), "{algorithm:?}");
        assert!(spc.ends_with(&format!("04{:02x}{}", digest.len(), hex(&digest))));
    }
}

/// Spec: SPC-4
/// A digest of the wrong length is refused.
#[test]
fn indirect_data_content_checks_the_digest_length() {
    assert_eq!(
        indirect_data_content(&[0x30, 0], HashAlgorithm::Sha256, &[0; 20]),
        Err(Error::DigestLength)
    );
}
