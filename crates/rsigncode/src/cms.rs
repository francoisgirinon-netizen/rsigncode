//! CMS `SignedData` (RFC 5652) as Authenticode uses it, signed with an RSA or ECDSA key.
//!
//! The layout is that of SignTool and osslsigncode: the `SpcIndirectDataContent` is the
//! encapsulated content (not wrapped in an `OCTET STRING`), the `messageDigest` attribute
//! is the digest of its contents without the tag and the length, and the signature covers
//! the DER of the signed attributes encoded as a `SET`.

use crate::hash::{HashAlgorithm, Hasher};
use crate::spc::{
    OID_SPC_MS_BASE, TAG_NULL, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET, attribute,
    digest_info, tlv,
};
use der::{Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use x509_cert::Certificate;

/// Why a signature could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A certificate is not valid DER, or there is none.
    Certificate,
    /// The `SpcIndirectDataContent` is not a DER `SEQUENCE`.
    IndirectData,
    /// The key is not an RSA, P-256 or P-384 key in PKCS#8 DER.
    Key,
    /// The key could not sign the digest.
    Signing,
}

/// Something that signs the digest of the signed attributes and knows the certificates that
/// go with the key: a key file, later a PKCS#11 token or a cloud service.
pub trait Signer {
    /// The DER certificates: the signer's first, then the chain.
    fn certificates(&self) -> &[Vec<u8>];

    /// The DER `AlgorithmIdentifier` of the signature, for the `signatureAlgorithm` field.
    fn signature_algorithm(&self, hash: HashAlgorithm) -> Vec<u8>;

    /// Signs `digest`, the hash computed with `hash`. RSA signatures are PKCS#1 v1.5, ECDSA
    /// signatures are DER `Ecdsa-Sig-Value`.
    fn sign_digest(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>, Error>;
}

enum Key {
    Rsa(Box<RsaPrivateKey>),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

/// A [`Signer`] for a private key held in memory.
pub struct KeySigner {
    key: Key,
    certificates: Vec<Vec<u8>>,
}

impl KeySigner {
    /// Builds a signer from a PKCS#8 DER private key (RSA, P-256 or P-384) and the DER
    /// certificates, the one of the key first.
    pub fn from_pkcs8_der(key: &[u8], certificates: Vec<Vec<u8>>) -> Result<Self, Error> {
        if certificates.is_empty() || certificates.iter().any(|c| parse(c).is_err()) {
            return Err(Error::Certificate);
        }
        let key = if let Ok(k) = RsaPrivateKey::from_pkcs8_der(key) {
            Key::Rsa(Box::new(k))
        } else if let Ok(k) = p256::ecdsa::SigningKey::from_pkcs8_der(key) {
            Key::P256(k)
        } else if let Ok(k) = p384::ecdsa::SigningKey::from_pkcs8_der(key) {
            Key::P384(k)
        } else {
            return Err(Error::Key);
        };
        Ok(KeySigner { key, certificates })
    }
}

impl Signer for KeySigner {
    fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }

    fn signature_algorithm(&self, hash: HashAlgorithm) -> Vec<u8> {
        match self.key {
            // rsaEncryption with NULL parameters, as SignTool writes it.
            Key::Rsa(_) => algorithm_identifier(OID_RSA_ENCRYPTION, true),
            Key::P256(_) | Key::P384(_) => {
                let mut oid = OID_ECDSA_WITH_SHA.to_vec();
                oid.push(match hash {
                    HashAlgorithm::Sha1 => return algorithm_identifier(OID_ECDSA_WITH_SHA1, false),
                    HashAlgorithm::Sha256 => 2,
                    HashAlgorithm::Sha384 => 3,
                    HashAlgorithm::Sha512 => 4,
                });
                algorithm_identifier(&oid, false)
            }
        }
    }

    fn sign_digest(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.key {
            Key::Rsa(key) => key
                .sign(Pkcs1v15Sign::new_unprefixed(), &digest_info(hash, digest))
                .map_err(|_| Error::Signing),
            Key::P256(key) => {
                let signature: p256::ecdsa::Signature =
                    key.sign_prehash(digest).map_err(|_| Error::Signing)?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            Key::P384(key) => {
                let signature: p384::ecdsa::Signature =
                    key.sign_prehash(digest).map_err(|_| Error::Signing)?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    }
}

/// 1.2.840.113549.1.7.2, `signedData`.
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// 1.2.840.113549.1.9.3, `contentType`.
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// 1.2.840.113549.1.9.4, `messageDigest`.
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// 1.2.840.113549.1.1.1, `rsaEncryption`.
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// 1.2.840.10045.4.1, `ecdsa-with-SHA1`.
const OID_ECDSA_WITH_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
/// 1.2.840.10045.4.3, to which 2, 3 or 4 is appended for `ecdsa-with-SHA256`, `-SHA384`
/// and `-SHA512`.
const OID_ECDSA_WITH_SHA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03];

fn algorithm_identifier(oid: &[u8], null_parameters: bool) -> Vec<u8> {
    let mut content = tlv(TAG_OID, oid);
    if null_parameters {
        content.extend_from_slice(&[TAG_NULL, 0]);
    }
    tlv(TAG_SEQUENCE, &content)
}

fn hash_algorithm_identifier(hash: HashAlgorithm) -> Vec<u8> {
    let info = digest_info(hash, &[]);
    // DigestInfo { AlgorithmIdentifier, OCTET STRING }: the identifier is its first element.
    let (content, _) = element(&info).expect("built by digest_info");
    let (_, length) = element(content).expect("built by digest_info");
    content[..length].to_vec()
}

/// The content of the first DER element and the total length of the element.
fn element(data: &[u8]) -> Option<(&[u8], usize)> {
    let first = *data.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(2..2 + count)?;
        (
            bytes.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b)),
            2 + count,
        )
    };
    let content = data.get(header..header.checked_add(len)?)?;
    Some((content, header + len))
}

fn parse(certificate: &[u8]) -> Result<Certificate, Error> {
    Certificate::from_der(certificate).map_err(|_| Error::Certificate)
}

/// `SET OF` in DER: the elements sorted by their encoding (X.690 11.6).
fn set_of(mut elements: Vec<Vec<u8>>) -> Vec<u8> {
    elements.sort();
    tlv(TAG_SET, &elements.concat())
}

/// Builds the `ContentInfo` holding the `SignedData` of a PE file.
///
/// `indirect_data` is the DER `SpcIndirectDataContent`; `attributes` are the other signed
/// attributes, each a complete DER `Attribute` (`spc::opus_info_attribute`,
/// `spc::statement_type_attribute`). The `contentType` and `messageDigest` attributes are
/// added here. `hash` is the algorithm of the file digest, also used for the signature.
pub fn signed_data(
    signer: &dyn Signer,
    hash: HashAlgorithm,
    indirect_data: &[u8],
    attributes: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let (indirect_content, total) = element(indirect_data).ok_or(Error::IndirectData)?;
    if indirect_data.first() != Some(&TAG_SEQUENCE) || total != indirect_data.len() {
        return Err(Error::IndirectData);
    }

    // The digest of the content, without its tag and length.
    let mut hasher = Hasher::new(hash);
    hasher.update(indirect_content);
    let message_digest = hasher.finalize();

    let mut indirect_oid = OID_SPC_MS_BASE.to_vec();
    indirect_oid.push(0x04);
    let mut signed_attributes = vec![
        attribute(OID_CONTENT_TYPE, &tlv(TAG_OID, &indirect_oid)),
        attribute(OID_MESSAGE_DIGEST, &tlv(TAG_OCTET_STRING, &message_digest)),
    ];
    signed_attributes.extend_from_slice(attributes);
    let signed_attributes = set_of(signed_attributes);

    let mut hasher = Hasher::new(hash);
    hasher.update(&signed_attributes);
    let signature = signer.sign_digest(hash, &hasher.finalize())?;

    let certificates = signer.certificates();
    let signer_certificate = parse(certificates.first().ok_or(Error::Certificate)?)?;
    let tbs = signer_certificate.tbs_certificate();
    let mut issuer_and_serial = tbs.issuer().to_der().map_err(|_| Error::Certificate)?;
    issuer_and_serial.extend_from_slice(
        &tbs.serial_number()
            .to_der()
            .map_err(|_| Error::Certificate)?,
    );

    // SignerInfo { version 1, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm,
    // signature }
    let mut signer_info = vec![0x02, 0x01, 0x01];
    signer_info.extend_from_slice(&tlv(TAG_SEQUENCE, &issuer_and_serial));
    signer_info.extend_from_slice(&hash_algorithm_identifier(hash));
    // The signed attributes go out as [0] IMPLICIT: the SET tag is replaced by 0xa0.
    let mut implicit = signed_attributes;
    implicit[0] = 0xa0;
    signer_info.extend_from_slice(&implicit);
    signer_info.extend_from_slice(&signer.signature_algorithm(hash));
    signer_info.extend_from_slice(&tlv(TAG_OCTET_STRING, &signature));

    // encapContentInfo { SPC_INDIRECT_DATA, [0] EXPLICIT SpcIndirectDataContent }
    let mut encapsulated = tlv(TAG_OID, &indirect_oid);
    encapsulated.extend_from_slice(&tlv(0xa0, indirect_data));

    // SignedData { version 1, digestAlgorithms, encapContentInfo, [0] certificates,
    // signerInfos }
    let mut signed = vec![0x02, 0x01, 0x01];
    signed.extend_from_slice(&set_of(vec![hash_algorithm_identifier(hash)]));
    signed.extend_from_slice(&tlv(TAG_SEQUENCE, &encapsulated));
    let mut set = set_of(certificates.to_vec());
    set[0] = 0xa0;
    signed.extend_from_slice(&set);
    signed.extend_from_slice(&set_of(vec![tlv(TAG_SEQUENCE, &signer_info)]));

    // ContentInfo { signedData, [0] EXPLICIT SignedData }
    let mut content_info = tlv(TAG_OID, OID_SIGNED_DATA);
    content_info.extend_from_slice(&tlv(0xa0, &tlv(TAG_SEQUENCE, &signed)));
    Ok(tlv(TAG_SEQUENCE, &content_info))
}
