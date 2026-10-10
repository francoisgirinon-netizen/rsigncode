//! PE32 and PE32+ files: parsing, Authenticode digest and image checksum.
//!
//! Everything works on a `&[u8]` (typically a memory map) and never panics on malformed
//! input: problems are reported as [`Error`].

mod checksum;
mod digest;
mod error;
mod page_hashes;
mod parser;
mod single_pass;

pub use checksum::checksum;
pub use digest::{HashAlgorithm, authenticode_digest};
pub use error::Error;
pub use page_hashes::page_hashes;
pub use parser::{PeFile, Section};
pub use single_pass::{Digests, digests};
