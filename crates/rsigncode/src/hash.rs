//! Hash functions behind one interface, so that the backend can be chosen at build time.
//!
//! Backends (Cargo features): `aws-lc` (default, aws-lc-rs) or `pure-rust` (RustCrypto
//! `sha1` and `sha2`). When both are enabled, `aws-lc` wins. See `DESIGN.md`.

#[cfg(not(any(feature = "aws-lc", feature = "pure-rust")))]
compile_error!("enable one hashing backend: the `aws-lc` (default) or `pure-rust` feature");

/// Hash algorithms supported for Authenticode.
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

impl HashAlgorithm {
    /// Length in bytes of the digest.
    pub fn output_len(self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

/// An incremental hash computation. It is [`Send`], so it can move to another thread.
pub struct Hasher(Inner);

impl Hasher {
    /// Starts a new computation.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Hasher(Inner::new(algorithm))
    }

    /// Feeds data to the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the digest.
    pub fn finalize(self) -> Vec<u8> {
        self.0.finalize()
    }
}

#[cfg(feature = "aws-lc")]
struct Inner(aws_lc_rs::digest::Context);

#[cfg(feature = "aws-lc")]
impl Inner {
    fn new(algorithm: HashAlgorithm) -> Self {
        use aws_lc_rs::digest;
        let algorithm = match algorithm {
            HashAlgorithm::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            HashAlgorithm::Sha256 => &digest::SHA256,
            HashAlgorithm::Sha384 => &digest::SHA384,
            HashAlgorithm::Sha512 => &digest::SHA512,
        };
        Inner(digest::Context::new(algorithm))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.0.finish().as_ref().to_vec()
    }
}

#[cfg(all(feature = "pure-rust", not(feature = "aws-lc")))]
enum Inner {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

#[cfg(all(feature = "pure-rust", not(feature = "aws-lc")))]
impl Inner {
    fn new(algorithm: HashAlgorithm) -> Self {
        use sha2::Digest;
        match algorithm {
            HashAlgorithm::Sha1 => Inner::Sha1(sha1::Sha1::new()),
            HashAlgorithm::Sha256 => Inner::Sha256(sha2::Sha256::new()),
            HashAlgorithm::Sha384 => Inner::Sha384(sha2::Sha384::new()),
            HashAlgorithm::Sha512 => Inner::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        match self {
            Inner::Sha1(h) => h.update(data),
            Inner::Sha256(h) => h.update(data),
            Inner::Sha384(h) => h.update(data),
            Inner::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Inner::Sha1(h) => h.finalize().to_vec(),
            Inner::Sha256(h) => h.finalize().to_vec(),
            Inner::Sha384(h) => h.finalize().to_vec(),
            Inner::Sha512(h) => h.finalize().to_vec(),
        }
    }
}
