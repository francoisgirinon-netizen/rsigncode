# Design

## Clean-room rule

rsigncode is licensed MIT OR Apache-2.0. osslsigncode is GPL-3.0, so its code must not
be copied or translated. The implementation follows the Microsoft specifications:

- [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows Authenticode Portable Executable Signature Format](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)
- [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool) for the
  command line behaviour and the detached signing workflow
- RFC 5652 (CMS), RFC 3161 (timestamps), RFC 5280 (X.509)

osslsigncode and SignTool are used as black boxes to compare outputs.

## Crates

- `rsigncode`: library. One module per file format, behind a common trait (compute the
  digest, build the content to sign, insert, extract and remove signatures).
- `rsigncode-cli`: the `rsigncode` command, with the same commands and option names as
  osslsigncode where it makes sense, so that it can replace it in scripts.

Building blocks: a small hand-written PE parser (`pe` module: it only needs a handful of
offsets, including the CheckSum field and the Certificate Table entry, which `object` does
not expose, and it must never panic on hostile input), RustCrypto (`cms`, `x509-cert`, `der`, `rsa`,
`p256`, `p384`, `sha1`, `sha2`), `p12` (PKCS#12), `cryptoki` (PKCS#11).

Signing goes through a `Signer` trait (sign a digest, return the certificate chain), with
implementations for key files, PKCS#11 and, later, cloud services.

## Large files

PE files can be close to 4 GB. Files are read through a memory map and hashed in one
pass. The patch mode of `attach-signature` writes only the bytes that change.

## Hashing backend

Hashing goes through `rsigncode::hash` (`Hasher::new(HashAlgorithm)`, `update`, `finalize`;
`Send`). Cargo features of `rsigncode` (forwarded by `rsigncode-cli`):

- `aws-lc` (default): `aws-lc-rs`, digest module (`SHA1_FOR_LEGACY_USE_ONLY`, `SHA256`,
  `SHA384`, `SHA512`). It needs a C compiler to build (and NASM on Windows, installed in CI
  with `ilammy/setup-nasm`).
- `pure-rust`: RustCrypto `sha1` and `sha2`, no C code. Used when `aws-lc` is disabled; if
  both are enabled `aws-lc` wins; if neither, `compile_error!`.

Measured on a Xeon E5-1620 v3 (no SHA-NI), MB/s on large buffers:

| | SHA-1 | SHA-256 | SHA-512 |
|---|---|---|---|
| RustCrypto `sha1`/`sha2` 0.11 | 537 | 204 | 373 |
| `aws-lc-rs` | 945 | 365 | 528 |
| OpenSSL (`openssl speed`) | - | 423 | - |

Why `aws-lc-rs` by default: signing is dominated by hashing multi-GB files, and on CPUs
without the SHA extensions it is 1.4 to 1.8 times faster than RustCrypto, close to
OpenSSL. Why not `ring`: its SHA-1 is slow (SHA-1 is still needed for dual signing). Why
not pure Rust by default: the portable SHA-256 is the slowest option, and the only fast
path in RustCrypto is the SHA-NI one
([RustCrypto/hashes#327](https://github.com/RustCrypto/hashes/issues/327) tracks the
missing assembly or AVX2 implementations). The `pure-rust` feature remains for platforms
without a C toolchain and is tested in CI.

## Performance

Method: generate a sparse PE of about 2 GB with `cargo run --release --example fixtures --
sparse <file> <MiB>` (outside `/tmp`, which is usually a small tmpfs), then compare, with
warm caches and `/usr/bin/time`, `cargo run --release --example digest -- <file> sha256`
(memory map plus `authenticode_digest`), `osslsigncode extract-data -h sha256` and
`openssl speed -evp sha256 -bytes 65536` (the CPU ceiling). Check that the digests are
identical.

Finding: the time is entirely spent in the hash compression function (system time and
copies are negligible), so throughput is that of the RustCrypto `sha1` and `sha2` crates.
On a CPU without the SHA extensions they use portable code (SHA-1, SHA-256) or a plain AVX2
backend (SHA-512), which is slower than the hand-tuned assembly of OpenSSL. Building with
`-C target-cpu=native` or the `asm` feature of `sha2` 0.10 does not close the gap. CPUs with
the SHA extensions use them (not measured here). The code feeds each hashed range to `update` in one call, so
the hash sees large contiguous slices and there is nothing left to gain in rsigncode
itself. Hashing a single stream cannot be parallelised.

## Testing

Development is test-driven: each feature starts with a failing test, then the minimal
code to make it pass, then refactoring. Expected values come from an independent oracle
(osslsigncode, SignTool or a value from a specification), never from rsigncode itself.

- Unit tests on small files in `tests/data`.
- Cross-checks against osslsigncode on Linux: same digests, page hashes and, with a fixed
  signing time, byte-identical output.
- Cross-checks against SignTool on a Windows runner (GitHub Actions): `signtool sign /dg`
  digests, `signtool verify /pa` on files signed by rsigncode.
- Sparse files above 2 GB in an optional slow test job.
