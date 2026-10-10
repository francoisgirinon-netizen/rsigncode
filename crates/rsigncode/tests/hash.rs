use rsigncode::hash::{HashAlgorithm, Hasher};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run(algorithm: HashAlgorithm, message: &[u8]) -> String {
    let mut h = Hasher::new(algorithm);
    // Feed in two pieces to check that `update` is incremental.
    let (a, b) = message.split_at(message.len() / 2);
    h.update(a);
    h.update(b);
    hex(&h.finalize())
}

const ABC: &[u8] = b"abc";
const EMPTY: &[u8] = b"";
const M448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

// Oracle: NIST FIPS 180-4 example values (SHA-1, SHA-256, SHA-384 and SHA-512 of "abc", of
// the empty message and of the 448-bit message), cross-checked with `openssl dgst`.
/// Spec: AUTH-PE-2, AUTH-PE-15 (hash contexts of the four algorithms), HASH-1.
#[test]
fn nist_fips_180_vectors() {
    let cases: &[(HashAlgorithm, &[u8], &str)] = &[
        (
            HashAlgorithm::Sha1,
            ABC,
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        ),
        (
            HashAlgorithm::Sha1,
            EMPTY,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ),
        (
            HashAlgorithm::Sha1,
            M448,
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        (
            HashAlgorithm::Sha256,
            ABC,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            HashAlgorithm::Sha256,
            EMPTY,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            HashAlgorithm::Sha256,
            M448,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            HashAlgorithm::Sha384,
            ABC,
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            HashAlgorithm::Sha384,
            EMPTY,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        ),
        (
            HashAlgorithm::Sha384,
            M448,
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
        ),
        (
            HashAlgorithm::Sha512,
            ABC,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            HashAlgorithm::Sha512,
            EMPTY,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            HashAlgorithm::Sha512,
            M448,
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        ),
    ];
    for (algorithm, message, expected) in cases {
        assert_eq!(run(*algorithm, message), *expected, "{algorithm:?}");
    }
}

/// Spec: HASH-2 (a hasher can move to another thread).
#[test]
fn hasher_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<Hasher>();
}
