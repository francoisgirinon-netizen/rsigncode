use crate::hash::Hasher;
use crate::pe::{Error, PeFile};

pub use crate::hash::HashAlgorithm;

/// Computes the Authenticode digest of a PE32 or PE32+ file.
///
/// The CheckSum field, the Certificate Table entry and the certificate table itself are
/// left out. A file without certificate table is hashed as if padded with zeros to a
/// multiple of 8 bytes, which is what signing does before appending the signature.
pub fn authenticode_digest(data: &[u8], algorithm: HashAlgorithm) -> Result<Vec<u8>, Error> {
    let pe = PeFile::parse(data)?;
    let hashed = pe.hashed_ranges()?;
    let mut hasher = Hasher::new(algorithm);
    for r in hashed.ranges {
        hasher.update(&pe.data[r]);
    }
    hasher.update(&[0u8; 8][..hashed.padding]);
    Ok(hasher.finalize())
}
