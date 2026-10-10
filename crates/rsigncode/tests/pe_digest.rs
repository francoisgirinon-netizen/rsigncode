mod common;

use common::{PeBuilder, fixtures};
use rsigncode::pe::{Error, HashAlgorithm, authenticode_digest};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn digest_hex(d: &[u8], a: HashAlgorithm) -> String {
    hex(&authenticode_digest(d, a).unwrap())
}

fn fixture(name: &str) -> Vec<u8> {
    fixtures().into_iter().find(|(n, _)| *n == name).unwrap().1
}

// Oracle: osslsigncode (master, Release) on the files written by
// `cargo run --example fixtures -- <dir>`:
//   osslsigncode extract-data -h sha256 -in <name>.exe -out x.der
//   openssl asn1parse -inform DER -in x.der      (last OCTET STRING of the DigestInfo)
const FIXTURE_SHA256: &[(&str, &str)] = &[
    (
        "pe32_aligned",
        "2a6f4cfe23bb0ee7e74020d27969e284ad0ccfdefbb308ea7c77014e24eadf19",
    ),
    (
        "pe32_extra_1",
        "8636bf955365b2c84a131650649a12da62e6cf19a5f871a905d452b248fd0c46",
    ),
    (
        "pe32_extra_2",
        "6e940b8a80ca03e74818e0b7173c0e1a84c96dbc2622c79bf4c4ef56f9536af3",
    ),
    (
        "pe32_extra_3",
        "e57d1456bb4d5e609491ec90fc623e52c91074d7b68155a36572c2034093c1b7",
    ),
    (
        "pe32_extra_4",
        "99d21a31498696f95f8ca0fcbef97656567b5b9ed6bd821376b6ac308a292f50",
    ),
    (
        "pe32_extra_5",
        "eae083627947c3ca46584eb3a81135212bddffdb721094341207e2ffc863f651",
    ),
    (
        "pe32_extra_6",
        "4605ff5faebe87ed9e6f6b220f93d66609e01a62e0bb33c3f9638905ed996cbc",
    ),
    (
        "pe32_extra_7",
        "8ce2d146783e49f86c812d67a0d04c9bc56d04b5c1582fd9befc95f9288a39e0",
    ),
    (
        "pe32_overlay_1000",
        "2d69c301d1be9f34d4f654a25a94fa572916421675b73393672211fc1b8f1212",
    ),
    (
        "pe32_reversed",
        "a38dcb279d2995eb26f634f07edae9db95b5e8fff48be0213d86da349edade56",
    ),
    (
        "pe64_aligned",
        "ecfc76cfa73b548a122688dd8fc9ec8df647c10e8754f8a12b51a1505fed600a",
    ),
    (
        "pe64_extra_1",
        "e9b3560492afc77040fa1164030eb3d0257d384752f3c4b77c760f839c7a7d41",
    ),
    (
        "pe64_extra_2",
        "e782c4c0bf74322c23fdff9ce8defc103de04bd395d6e6166c233326ee68fdf1",
    ),
    (
        "pe64_extra_3",
        "af0d44a219d70a8537c84430287cc2ab84092333ed539fa0087429ad7d4556fd",
    ),
    (
        "pe64_extra_4",
        "7c677ae1a55479c4b1864af64c16cda5b750d2526c05d81433f58ca4002e31fa",
    ),
    (
        "pe64_extra_5",
        "a4ed0db34698279c8ab9d33c30889d4a7bfcb7f3293635a54e2671bf2f72923c",
    ),
    (
        "pe64_extra_6",
        "eb89fdf9a89f6a4a47906467feea09ef5d3fbd727ed992f92df4eb62f22f8d2f",
    ),
    (
        "pe64_extra_7",
        "d8aaf951805e5aebe8feeef7004ce5671358c3e1f7a183ed802a8ac151c766ac",
    ),
    (
        "pe64_overlay_8",
        "f0f1e5df44c5b6d489394b8459abe7dfe47f45a66b7600bbe2d4ff1c86151673",
    ),
    (
        "pe64_reversed",
        "a9ebd293f88c546dae8a64b84ade45b3b15baaf9cc398c99ec2791943e6ac99c",
    ),
];

// Same oracle with -h sha1, sha256, sha384 and sha512: (name, sha1, sha256, sha384, sha512).
const ALL_ALGORITHMS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "pe32_extra_3",
        "4ea444021c9e1723c344b00113f3254a0250dd19",
        "e57d1456bb4d5e609491ec90fc623e52c91074d7b68155a36572c2034093c1b7",
        "1103ef90ed6b70c49e014d6775b588f211bed4b5a89215e73ac91115f3f9addd8573ad57d7ea22349953fd4811869bfb",
        "485000c2aa84456d9e130ec4029931758cefac7f074665397fd53c7b42ed8f91e3b00d5ae8d9aeec7f3a4345d1f02d353f7deefc30193964f82b86f58acb0099",
    ),
    (
        "pe64_aligned",
        "7fcd9ec7f8f29b042f8f3cc8e63f1939fce4f8a2",
        "ecfc76cfa73b548a122688dd8fc9ec8df647c10e8754f8a12b51a1505fed600a",
        "2f3214d13fc0b6368e0eb0cadbced6204eabd1087d346c19d1a3b4c5473bc7654dc23e50afe8db9d2bf4cf65bee2c1e8",
        "8d91f0e4491df7b283de2970734022c2595e31ae8c327dc56c8f01891b4ee258adac92c0d5b5d3a972d1641784e815cfb2860621070591cdd9477420976eea48",
    ),
    (
        "pe64_reversed",
        "ce15258200f4bedf54b450623d3ce1cd970bc01b",
        "a9ebd293f88c546dae8a64b84ade45b3b15baaf9cc398c99ec2791943e6ac99c",
        "437eba45180ec5dc5f80500d66daf7060ce22c0db2218e5526174f957652b6fd9650e3941bf021316dca37944076677e",
        "a0df837a0508229c4260ee8a854ee3f597f98a1eed8ecd6b4104eb7c82f35ea73bf3e8910b05e29ab73d1a1dc17a0179c66fdee25281f2a92319f837e27ad31a",
    ),
];

#[test]
fn sha256_of_every_fixture_matches_osslsigncode() {
    let all = fixtures();
    assert_eq!(all.len(), FIXTURE_SHA256.len());
    for (name, expected) in FIXTURE_SHA256 {
        let (_, bytes) = all.iter().find(|(n, _)| n == name).unwrap();
        assert_eq!(
            &digest_hex(bytes, HashAlgorithm::Sha256),
            expected,
            "{name}"
        );
    }
}

#[test]
fn all_four_algorithms_match_osslsigncode() {
    for (name, sha1, sha256, sha384, sha512) in ALL_ALGORITHMS {
        let d = fixture(name);
        let got = [
            digest_hex(&d, HashAlgorithm::Sha1),
            digest_hex(&d, HashAlgorithm::Sha256),
            digest_hex(&d, HashAlgorithm::Sha384),
            digest_hex(&d, HashAlgorithm::Sha512),
        ];
        let want = [sha1, sha256, sha384, sha512];
        for (g, w) in got.iter().zip(want) {
            if !w.is_empty() {
                assert_eq!(g, w, "{name}");
            }
        }
    }
}

// Oracle: osslsigncode extract-data on tests/data/tiny32.efi and tiny64.efi.
#[test]
fn tiny_efi_images_match_osslsigncode() {
    let cases = [
        (
            "tiny32.efi",
            HashAlgorithm::Sha1,
            "49f239f1cd5083912880e03982bb54528f2c358d",
        ),
        (
            "tiny32.efi",
            HashAlgorithm::Sha256,
            "4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8",
        ),
        (
            "tiny64.efi",
            HashAlgorithm::Sha1,
            "e9bdfb63bdf687b8d3bf144033fcb09d7a393563",
        ),
        (
            "tiny64.efi",
            HashAlgorithm::Sha256,
            "a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae",
        ),
    ];
    for (file, alg, want) in cases {
        assert_eq!(digest_hex(&data(file), alg), want, "{file}");
    }
}

// 2051 bytes: not a multiple of 8, so 5 zero bytes of padding are hashed.
// SHA-256: value from real SignTool 10.0.26100.0 (authenticode-rs test data). Without the
// padding it would be 2a9e8c97f066e6eee3c5a3e22cdf158c4f7b457d0834a4ec8955942bc109bdac.
// SHA-1: osslsigncode extract-data -h sha1.
#[test]
fn unsigned_file_with_odd_size_is_padded_like_signtool() {
    let mut d = data("tiny64.efi");
    d.extend_from_slice(&[1, 2, 3]);
    assert_eq!(d.len(), 2051);
    assert_eq!(
        digest_hex(&d, HashAlgorithm::Sha256),
        "17b7398abe837540f81e53ab8c4913cc57f3c25d8ab8dcc7f9f60e22563ccd90"
    );
    assert_eq!(
        digest_hex(&d, HashAlgorithm::Sha1),
        "051c27f3914bda5d3bb1b1c3ba4284509862543a"
    );
}

// Signed with: osslsigncode sign -certs c.pem -key k.pem -h sha256 -time 1556668800
// (throw-away self-signed key). Digest taken from `osslsigncode verify`
// ("Current message digest" == "Calculated message digest"), equal to the unsigned digest.
#[test]
fn files_signed_by_osslsigncode_have_the_digest_of_the_unsigned_file() {
    let cases = [
        (
            "pe32_extra_3.signed.exe",
            "e57d1456bb4d5e609491ec90fc623e52c91074d7b68155a36572c2034093c1b7",
        ),
        (
            "pe64_aligned.signed.exe",
            "ecfc76cfa73b548a122688dd8fc9ec8df647c10e8754f8a12b51a1505fed600a",
        ),
    ];
    for (file, want) in cases {
        assert_eq!(
            digest_hex(&data(file), HashAlgorithm::Sha256),
            want,
            "{file}"
        );
    }
}

// tiny64.signed.efi was signed by SignTool: its digest must be the one of tiny64.efi.
#[test]
fn file_signed_by_signtool_has_the_digest_of_the_unsigned_file() {
    for alg in [HashAlgorithm::Sha1, HashAlgorithm::Sha256] {
        assert_eq!(
            digest_hex(&data("tiny64.signed.efi"), alg),
            digest_hex(&data("tiny64.efi"), alg)
        );
    }
}

#[test]
fn digest_lengths() {
    let d = fixture("pe32_aligned");
    for (a, n) in [
        (HashAlgorithm::Sha1, 20),
        (HashAlgorithm::Sha256, 32),
        (HashAlgorithm::Sha384, 48),
        (HashAlgorithm::Sha512, 64),
    ] {
        assert_eq!(authenticode_digest(&d, a).unwrap().len(), n);
    }
}

#[test]
fn checksum_field_and_certificate_entry_are_not_hashed() {
    let a = fixture("pe32_aligned");
    let mut b = a.clone();
    b[0xE8..0xEC].copy_from_slice(&[9, 9, 9, 9]); // CheckSum
    assert_eq!(
        digest_hex(&a, HashAlgorithm::Sha256),
        digest_hex(&b, HashAlgorithm::Sha256)
    );
    let mut c = a.clone();
    c[0x7F] ^= 1; // padding of the DOS header: hashed
    assert_ne!(
        digest_hex(&a, HashAlgorithm::Sha256),
        digest_hex(&c, HashAlgorithm::Sha256)
    );
}

#[test]
fn every_truncation_inside_the_headers_or_sections_is_an_error() {
    for pe32plus in [false, true] {
        let d = PeBuilder::new(pe32plus).sections(&[0x200, 0x200]).build();
        // Headers and section data end at 0x200 (headers) + 0x400.
        for len in 0..d.len() {
            assert!(
                authenticode_digest(&d[..len], HashAlgorithm::Sha256).is_err(),
                "len {len} pe32plus {pe32plus}"
            );
        }
        assert!(authenticode_digest(&d, HashAlgorithm::Sha256).is_ok());
    }
}

#[test]
fn bad_signatures_and_magic_are_reported() {
    let d = fixture("pe32_aligned");
    let mut x = d.clone();
    x[0] = b'Z';
    assert_eq!(
        authenticode_digest(&x, HashAlgorithm::Sha1),
        Err(Error::BadDosSignature)
    );
    let mut x = d.clone();
    x[0x80] = b'X';
    assert_eq!(
        authenticode_digest(&x, HashAlgorithm::Sha1),
        Err(Error::BadPeSignature)
    );
    let mut x = d.clone();
    x[0x98] = 0x07; // optional header magic
    assert_eq!(
        authenticode_digest(&x, HashAlgorithm::Sha1),
        Err(Error::UnknownOptionalHeaderMagic)
    );
    let mut x = d.clone();
    x[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes()); // e_lfanew out of the file
    assert_eq!(
        authenticode_digest(&x, HashAlgorithm::Sha1),
        Err(Error::Truncated)
    );
}

#[test]
fn section_beyond_the_end_of_the_file_is_an_error() {
    let mut d = fixture("pe32_aligned");
    // First section header: SizeOfRawData at +16.
    let sh = 0x80 + 24 + 224;
    d[sh + 16..sh + 20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        authenticode_digest(&d, HashAlgorithm::Sha1),
        Err(Error::SectionOutOfBounds)
    );
}

#[test]
fn certificate_table_outside_the_file_is_an_error() {
    let mut d = fixture("pe32_aligned");
    let entry = 0x80 + 24 + 96 + 32;
    d[entry..entry + 4].copy_from_slice(&0x7fff_0000u32.to_le_bytes());
    d[entry + 4..entry + 8].copy_from_slice(&0x100u32.to_le_bytes());
    assert_eq!(
        authenticode_digest(&d, HashAlgorithm::Sha1),
        Err(Error::InvalidCertificateTable)
    );
}

#[test]
fn fewer_than_five_data_directories_is_an_error() {
    let mut d = fixture("pe32_aligned");
    let nrva = 0x80 + 24 + 92;
    d[nrva..nrva + 4].copy_from_slice(&4u32.to_le_bytes());
    assert_eq!(
        authenticode_digest(&d, HashAlgorithm::Sha1),
        Err(Error::MissingCertificateDirectory)
    );
}

#[test]
fn random_corruption_never_panics() {
    let base = PeBuilder::new(true)
        .sections(&[0x200, 0x200])
        .overlay_len(13)
        .build();
    let mut x: u32 = 0x1234_5678;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    for _ in 0..20_000 {
        let mut d = base.clone();
        for _ in 0..1 + next() % 4 {
            // Mostly in the headers, where the interesting fields are.
            let limit = if next() % 4 == 0 { d.len() } else { 0x200 };
            let i = next() as usize % limit;
            d[i] = next() as u8;
        }
        if next() % 8 == 0 {
            d.truncate(next() as usize % d.len());
        }
        let _ = authenticode_digest(&d, HashAlgorithm::Sha256);
        let _ = rsigncode::pe::checksum(&d);
    }
}
