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

/// The DER elements (tag, length and content) that follow one another in `der`.
fn elements(mut der: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let (header, len) = match der[1] {
            n if n < 0x80 => (2, usize::from(n)),
            n => {
                let count = usize::from(n & 0x7f);
                let len = der[2..2 + count]
                    .iter()
                    .fold(0, |len, b| (len << 8) | usize::from(*b));
                (2 + count, len)
            }
        };
        out.push(&der[..header + len]);
        der = &der[header + len..];
    }
    out
}

/// The elements inside a constructed DER element.
fn children(element: &[u8]) -> Vec<&[u8]> {
    let header = if element[1] < 0x80 {
        2
    } else {
        2 + usize::from(element[1] & 0x7f)
    };
    elements(&element[header..])
}

/// The length of the content of a DER element.
fn content_len(element: &[u8]) -> usize {
    element.len()
        - if element[1] < 0x80 {
            2
        } else {
            2 + usize::from(element[1] & 0x7f)
        }
}

/// What a `ContentInfo` of a PE signature holds, field by field.
struct Parts<'a> {
    version: &'a [u8],
    digest_algorithms: &'a [u8],
    encapsulated: &'a [u8],
    certificates: usize,
    signer_info_version: &'a [u8],
    digest_algorithm: &'a [u8],
    signed_attributes: &'a [u8],
    signature_algorithm: &'a [u8],
    signature_len: usize,
}

fn parts(content_info: &[u8]) -> Parts<'_> {
    let signed_data = children(children(content_info)[1])[0];
    let fields = children(signed_data);
    let signer_info = children(children(fields[4])[0]);
    Parts {
        version: fields[0],
        digest_algorithms: fields[1],
        encapsulated: fields[2],
        certificates: children(fields[3]).len(),
        signer_info_version: signer_info[0],
        digest_algorithm: signer_info[2],
        signed_attributes: signer_info[3],
        signature_algorithm: signer_info[4],
        signature_len: content_len(signer_info[5]),
    }
}

/// Spec: SIGNTOOL-CMS-1
/// Fed with the `SpcIndirectDataContent` that SignTool signed (with `/ph`), the `SignedData`
/// of rsigncode is, apart from the certificate, the signer identifier and the signature
/// value (they depend on the key), the one SignTool writes: same version, digest
/// algorithms, encapsulated content, signed attributes (the empty `SpcSpOpusInfo`, the
/// content type, the individual statement type and the message digest, in DER order, no
/// signing time), `rsaEncryption` signature algorithm and signature length.
///
/// `tests/data/signtool_<alg>.p7` are the signatures of `pe32_extra_3.exe` made by
/// SignTool 4.00 (Windows SDK 10.0.26100) in the `signtool-oracle` workflow.
#[test]
fn signed_data_matches_signtool() {
    for (name, hash) in [
        ("sha1", HashAlgorithm::Sha1),
        ("sha256", HashAlgorithm::Sha256),
        ("sha384", HashAlgorithm::Sha384),
        ("sha512", HashAlgorithm::Sha512),
    ] {
        let signtool_file = data_file(&format!("signtool_{name}.p7"));
        let signtool = parts(&signtool_file);
        // encapContentInfo { OID, [0] { SpcIndirectDataContent } }
        let indirect = children(children(signtool.encapsulated)[1])[0];

        let attributes = vec![
            opus_info_attribute(None, None).unwrap(),
            statement_type_attribute(StatementType::Individual),
        ];
        let ours_file = signed_data(&signer("rsa2048"), hash, indirect, &attributes).unwrap();
        let ours = parts(&ours_file);

        assert_eq!(ours.version, signtool.version, "{name} version");
        assert_eq!(ours.digest_algorithms, signtool.digest_algorithms, "{name}");
        assert_eq!(ours.encapsulated, signtool.encapsulated, "{name} content");
        assert_eq!(ours.certificates, signtool.certificates, "{name}");
        assert_eq!(ours.signer_info_version, signtool.signer_info_version);
        assert_eq!(ours.digest_algorithm, signtool.digest_algorithm, "{name}");
        assert_eq!(ours.signed_attributes, signtool.signed_attributes, "{name}");
        assert_eq!(
            ours.signature_algorithm, signtool.signature_algorithm,
            "{name}"
        );
        assert_eq!(ours.signature_len, signtool.signature_len, "{name}");
    }
}
