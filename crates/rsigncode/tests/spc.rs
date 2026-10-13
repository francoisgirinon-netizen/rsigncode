use rsigncode::pe::{HashAlgorithm, authenticode_digest, page_hashes};
use rsigncode::spc::{
    Error, PeImageFlags, StatementType, indirect_data_content, opus_info, opus_info_attribute,
    pe_image_data, pe_image_data_with_page_hashes, statement_type_attribute,
};

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

/// Spec: SPC-9
/// With page hashes, `file` is a moniker `SpcSerializedObject` (class id of
/// `SpcPeImageData`) whose data is `SET { SEQUENCE { 1.3.6.1.4.1.311.2.3.1, SET { OCTET
/// STRING table } } }` (V1, SHA-1). Layout written from osslsigncode's structures: no real
/// signature in `tests/data` has page hashes, so this one is not checked against a file.
#[test]
fn pe_image_data_with_sha1_page_hashes_layout() {
    let table = [
        vec![0, 0, 0, 0],
        vec![0x11; 20],
        vec![0, 0, 0x10, 0],
        vec![0; 20],
    ]
    .concat();
    let der = pe_image_data_with_page_hashes(
        PeImageFlags::INCLUDE_RESOURCES,
        HashAlgorithm::Sha1,
        &table,
    )
    .unwrap();
    let expected = format!(
        "3060 03020780 a05a a158 0410a6b586d5b4a12466ae05a217da8e60d6 0444 3142 3040 060a2b06010401823702030 1 3132 0430{}",
        hex(&table)
    )
    .replace(' ', "");
    assert_eq!(hex(&der), expected);
}

/// Spec: SPC-10
/// SHA-256 page hashes use the V2 object identifier (1.3.6.1.4.1.311.2.3.2), the table is
/// carried unchanged (here the table of a real image, 17 entries or fewer).
#[test]
fn pe_image_data_with_sha256_page_hashes_uses_v2() {
    let data = data_file("tiny64.efi");
    let table = page_hashes(&data, HashAlgorithm::Sha256).unwrap();
    let der =
        hex(
            &pe_image_data_with_page_hashes(PeImageFlags::NONE, HashAlgorithm::Sha256, &table)
                .unwrap(),
        );
    assert!(der.contains("060a2b06010401823702030231"));
    assert!(der.ends_with(&hex(&table)));
}

/// Spec: SPC-11
/// Page hashes exist for SHA-1 and SHA-256 only, and the table must be whole entries.
#[test]
fn page_hash_arguments_are_checked() {
    for algorithm in [HashAlgorithm::Sha384, HashAlgorithm::Sha512] {
        assert_eq!(
            pe_image_data_with_page_hashes(PeImageFlags::NONE, algorithm, &[0; 52]),
            Err(Error::PageHashAlgorithm)
        );
    }
    for len in [0, 23, 25] {
        assert_eq!(
            pe_image_data_with_page_hashes(PeImageFlags::NONE, HashAlgorithm::Sha1, &vec![0; len]),
            Err(Error::PageHashTable)
        );
    }
}

/// Spec: SPC-5
/// The statement type attribute: the individual one is the attribute osslsigncode wrote in
/// `pe32_extra_3.signed.exe`; the commercial one differs by the last OID arc (22).
#[test]
fn statement_type_attribute_matches_osslsigncode() {
    assert_eq!(
        hex(&statement_type_attribute(StatementType::Individual)),
        "301c060a2b06010401823702010b310e300c060a2b060104018237020115"
    );
    assert_eq!(
        hex(&statement_type_attribute(StatementType::Commercial)),
        "301c060a2b06010401823702010b310e300c060a2b060104018237020116"
    );
}

/// Spec: SPC-6
/// `SpcSpOpusInfo`: `programName [0] { [0] BMPString }` (`-n`), `moreInfo [1] { [0] IA5String }`
/// (`-i`), both optional. Layout of the structure, written from the definition used by
/// osslsigncode (no real signature in `tests/data` carries one).
#[test]
fn opus_info_layout() {
    assert_eq!(hex(&opus_info(None, None).unwrap()), "3000");
    assert_eq!(
        hex(&opus_info(Some("Test"), None).unwrap()),
        "300ca00a80080054006500730074"
    );
    assert_eq!(
        hex(&opus_info(None, Some("http://a")).unwrap()),
        "300ca10a8008687474703a2f2f61"
    );
    assert_eq!(
        hex(&opus_info(Some("Test"), Some("http://a")).unwrap()),
        "3018a00a80080054006500730074a10a8008687474703a2f2f61"
    );
    // The attribute wraps the value in `SEQUENCE { 1.3.6.1.4.1.311.2.1.12, SET { value } }`.
    assert_eq!(
        hex(&opus_info_attribute(Some("Test"), Some("http://a")).unwrap()),
        "3028060a2b06010401823702010c311a3018a00a80080054006500730074a10a8008687474703a2f2f61"
    );
}

/// Spec: SPC-7
/// Non-ASCII program names are UTF-16BE; a URL longer than 127 bytes uses the long length
/// form.
#[test]
fn opus_info_encodings() {
    assert_eq!(
        hex(&opus_info(Some("é€"), None).unwrap()),
        "3008a006800400e920ac"
    );
    // 207 bytes of URL: three nested long-form lengths (81 cf, 81 d2, 81 d5).
    let url = format!("http://{}", "a".repeat(200));
    let der = opus_info(None, Some(&url)).unwrap();
    assert_eq!(hex(&der[..8]), "3081d5a181d28081");
    assert_eq!(der.len(), 216);
}

/// Spec: SPC-8
/// A program name outside the BMP or a non-ASCII URL cannot be encoded.
#[test]
fn opus_info_rejects_unencodable_text() {
    assert_eq!(
        opus_info(Some("a\u{1f600}"), None),
        Err(Error::ProgramNameNotBmp)
    );
    assert_eq!(opus_info(None, Some("http://é")), Err(Error::UrlNotAscii));
    assert_eq!(
        opus_info_attribute(Some("\u{1f600}"), None),
        Err(Error::ProgramNameNotBmp)
    );
}
