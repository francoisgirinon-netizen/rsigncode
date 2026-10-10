use crate::pe::Error;

/// Computes the PE image checksum, as `CheckSumMappedFile` does.
pub fn checksum(_data: &[u8]) -> Result<u32, Error> {
    Err(Error::Unimplemented)
}
