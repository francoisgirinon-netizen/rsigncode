//! `cargo run --example cms -- <dir>`
//!
//! Writes to `<dir>` the `SignedData` (`<key>-<hash>.p7`) that rsigncode builds with the test
//! keys of `tests/data` (RSA 2048, ECDSA P-256 and P-384) for every digest algorithm. The
//! Windows workflow `signtool-oracle` has CryptoAPI check them (`ci/verify_cms.ps1`).

use rsigncode::cms::{KeySigner, signed_data};
use rsigncode::pe::HashAlgorithm;
use rsigncode::spc::{
    PeImageFlags, StatementType, indirect_data_content, opus_info_attribute, pe_image_data,
    statement_type_attribute,
};

fn data_file(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: cms <dir>: where to write the signatures");
    std::fs::create_dir_all(&dir).unwrap();
    for key in ["rsa2048", "p256", "p384"] {
        let signer = KeySigner::from_pkcs8_der(
            &data_file(&format!("cms_{key}.key.der")),
            vec![data_file(&format!("cms_{key}.cert.der"))],
        )
        .unwrap();
        for (name, hash) in [
            ("sha1", HashAlgorithm::Sha1),
            ("sha256", HashAlgorithm::Sha256),
            ("sha384", HashAlgorithm::Sha384),
            ("sha512", HashAlgorithm::Sha512),
        ] {
            let digest = vec![0x5a; hash.output_len()];
            let indirect =
                indirect_data_content(&pe_image_data(PeImageFlags::NONE), hash, &digest).unwrap();
            let attributes = [
                opus_info_attribute(None, None).unwrap(),
                statement_type_attribute(StatementType::Individual),
            ];
            let signature = signed_data(&signer, hash, &indirect, &attributes).unwrap();
            std::fs::write(format!("{dir}/{key}-{name}.p7"), signature).unwrap();
        }
    }
}
