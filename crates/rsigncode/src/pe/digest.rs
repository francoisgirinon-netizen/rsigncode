use crate::pe::{Error, PeFile};
use digest::Digest;

/// Hash algorithms supported for the Authenticode digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-1 (20 bytes).
    Sha1,
    /// SHA-256 (32 bytes).
    Sha256,
    /// SHA-384 (48 bytes).
    Sha384,
    /// SHA-512 (64 bytes).
    Sha512,
}

/// Computes the Authenticode digest of a PE32 or PE32+ file.
///
/// The CheckSum field, the Certificate Table entry and the certificate table itself are
/// left out. A file without certificate table is hashed as if padded with zeros to a
/// multiple of 8 bytes, which is what signing does before appending the signature.
pub fn authenticode_digest(data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, Error> {
    let pe = PeFile::parse(data)?;
    Ok(match algorithm {
        HashAlgorithm::Sha1 => hash::<sha1::Sha1>(&pe)?,
        HashAlgorithm::Sha256 => hash::<sha2::Sha256>(&pe)?,
        HashAlgorithm::Sha384 => hash::<sha2::Sha384>(&pe)?,
        HashAlgorithm::Sha512 => hash::<sha2::Sha512>(&pe)?,
    })
}

fn hash<D: Digest>(pe: &PeFile<'_>) -> Result<Vec<u8>, Error> {
    let hashed = pe.hashed_ranges()?;
    let mut hasher = D::new();
    for r in hashed.ranges {
        hasher.update(&pe.data[r]);
    }
    hasher.update(&[0u8; 8][..hashed.padding]);
    Ok(hasher.finalize().to_vec())
}
