use rsigncode::cms::{Error, KeySigner, signed_data};
use rsigncode::pe::HashAlgorithm;
use rsigncode::spc::{
    PeImageFlags, StatementType, indirect_data_content, opus_info_attribute, pe_image_data,
    statement_type_attribute,
};
use std::process::Command;

fn data_file(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn signer(key: &str) -> KeySigner {
    KeySigner::from_pkcs8_der(
        &data_file(&format!("cms_{key}.key.der")),
        vec![data_file(&format!("cms_{key}.cert.der"))],
    )
    .unwrap()
}

const ALGORITHMS: [HashAlgorithm; 4] = [
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
];

fn sign(key: &str, hash: HashAlgorithm) -> Vec<u8> {
    let digest = vec![0x5a; hash.output_len()];
    let indirect =
        indirect_data_content(&pe_image_data(PeImageFlags::NONE), hash, &digest).unwrap();
    let attributes = vec![
        opus_info_attribute(Some("rsigncode"), Some("https://example.com")).unwrap(),
        statement_type_attribute(StatementType::Individual),
    ];
    signed_data(&signer(key), hash, &indirect, &attributes).unwrap()
}

/// `openssl smime -verify` (the PKCS#7 API, which takes the Authenticode content as is) of the signature alone (`-noverify`: the certificates are
/// self-signed and not trusted). `None` when openssl is not installed.
fn openssl_verifies(signature: &[u8], name: &str) -> Option<bool> {
    let dir = std::env::temp_dir().join(format!("rsigncode-cms-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("sig.der");
    std::fs::write(&file, signature).unwrap();
    let output = Command::new("openssl")
        .args([
            "smime",
            "-verify",
            "-inform",
            "DER",
            "-noverify",
            "-binary",
            "-in",
        ])
        .arg(&file)
        .args(["-out"])
        .arg(dir.join("content"))
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Some(output.status.success())
}

/// Spec: CMS-1
/// The signature of every key type and digest algorithm verifies with OpenSSL.
#[test]
fn signatures_verify_with_openssl() {
    for key in ["rsa2048", "p256", "p384"] {
        for hash in ALGORITHMS {
            let signature = sign(key, hash);
            match openssl_verifies(&signature, &format!("{key}-{hash:?}")) {
                Some(ok) => assert!(ok, "{key} {hash:?}"),
                None => return,
            }
        }
    }
}

/// Spec: CMS-2
/// A signature that was changed does not verify: the check above is not vacuous.
#[test]
fn a_modified_signature_does_not_verify() {
    let mut signature = sign("p256", HashAlgorithm::Sha256);
    // The last bytes are the signature value.
    let last = signature.len() - 1;
    signature[last] ^= 1;
    if let Some(ok) = openssl_verifies(&signature, "tampered") {
        assert!(!ok);
    }
}

/// Spec: CMS-3
/// What is wrong with the input is reported, not signed.
#[test]
fn bad_input_is_an_error() {
    assert_eq!(
        KeySigner::from_pkcs8_der(&data_file("cms_p256.key.der"), vec![]).err(),
        Some(Error::Certificate)
    );
    assert_eq!(
        KeySigner::from_pkcs8_der(&data_file("cms_p256.key.der"), vec![vec![1, 2, 3]]).err(),
        Some(Error::Certificate)
    );
    assert_eq!(
        KeySigner::from_pkcs8_der(&[1, 2, 3], vec![data_file("cms_p256.cert.der")]).err(),
        Some(Error::Key)
    );
    // Truncated, a length that is not DER (indefinite, more than 4 bytes), the wrong tag
    // and bytes after the element.
    for indirect in [
        &[0x30, 0x01][..],
        &[0x30, 0x80],
        &[0x30, 0x85, 0, 0, 0, 0, 0],
        &[0x31, 0x00],
        &[0x30, 0x00, 0x00],
    ] {
        assert_eq!(
            signed_data(&signer("p256"), HashAlgorithm::Sha256, indirect, &[]),
            Err(Error::IndirectData)
        );
    }
}
