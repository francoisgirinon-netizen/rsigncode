use crate::pe::Error;

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

/// Computes the Authenticode digest of a PE file.
pub fn authenticode_digest(_data: &[u8], _algorithm: HashAlgorithm) -> Result<Vec<u8>, Error> {
    Err(Error::Unimplemented)
}
