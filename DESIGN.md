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
`p256`, `p384`), `aws-lc-rs` or RustCrypto `sha1` and `sha2` for hashing (see below), `p12` (PKCS#12), `cryptoki` (PKCS#11).

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
copies are negligible), so throughput is that of the hash backend. On a CPU without the
SHA extensions the RustCrypto crates use portable code (SHA-1, SHA-256) or a plain AVX2
backend (SHA-512), which is slower than the hand-tuned assembly of OpenSSL and aws-lc.
Building with `-C target-cpu=native` or the `asm` feature of `sha2` 0.10 does not close the
gap. The code feeds each hashed range to `update` in one call, so the hash sees large
contiguous slices and there is nothing left to gain in rsigncode itself. Hashing a single
stream cannot be parallelised.

### Page hashes and the single pass

Page hashes (`-ph`) hash every byte of the sections a second time, with the page hash
algorithm, so the sequential cost is twice that of the digest alone. `pe::digests` computes
everything in one call over one mapping: one thread per file digest algorithm (one per
algorithm: a stream cannot be split, so SHA-1 + SHA-256 dual signing runs both at once), and
the pages split into contiguous groups, one `std::thread::scope` worker per remaining core
(at least one). No dependency is needed for that (no rayon): the work is a fixed number of
equal-cost chunks, there is no work stealing to gain. The output is byte-identical to the
sequential functions (tested).

Command: `cargo run --release --example fixtures -- sparse ~/.cache/rsigncode/sparse2g.exe
2048` then `cargo run --release --example perf -- ~/.cache/rsigncode/sparse2g.exe 2` (best
of 2 runs, warm cache, 2147 MB file, page hashes use SHA-256, 4 KiB pages). MB/s are 10^6
bytes of file per second.

| Operation | local i7-7700HQ (4C/8T) aws-lc | local pure-rust | sota E5-1620 v3 (4C/8T, no SHA-NI) aws-lc | sota pure-rust |
|---|---|---|---|---|
| SHA-256 digest, sequential | 302 | 185 | 348 | 202 |
| SHA-256 digest + page hashes, sequential | 151 | 95 | 173 | 100 |
| SHA-256 digest + page hashes, single pass | 266 | 163 | 292 | 168 |
| SHA-256 digest only, `digests` | 308 | 181 | 361 | 202 |
| SHA-1 + SHA-256 digests, sequential | 206 | 132 | 251 | 144 |
| SHA-1 + SHA-256 digests + page hashes, sequential | 125 | 82 | 150 | 83 |
| SHA-1 + SHA-256 digests + page hashes, single pass | 256 | 162 | 298 | 161 |

With page hashes the single pass is 1.7 to 2.0 times faster than the sequential code, and
with aws-lc it runs at 81 to 86% of the speed of the digest alone (SHA-256 only), or 80 to
83% of it with SHA-1 + SHA-256. The remaining gap is the 4 physical cores: the digest and
the page hashes hash the section bytes twice.

Reference (same files, `osslsigncode` built from the local checkout, Release, OpenSSL 3):

| Local i7-7700HQ | time | MB/s |
|---|---|---|
| `openssl speed -evp sha256 -bytes 65536` | | 400 |
| `osslsigncode extract-data -h sha256` | 5.6 s | 383 |
| `osslsigncode extract-data -ph -h sha256` | 11.6 s | 185 |
| `osslsigncode sign -h sha256` | 7.9 s | 272 |
| `osslsigncode sign -ph -h sha256` | 14.8 s | 145 |

On sota, `openssl speed` gives 417 MB/s (SHA-256) and 936 MB/s (SHA-1); osslsigncode is not
installed there and nothing may be installed, so it was not run. On the local machine
the sequential aws-lc digest (302 MB/s) is 20% slower than osslsigncode's (383 MB/s),
whereas aws-lc-rs and OpenSSL are close on sota (365 / 423 MB/s on buffers): not
investigated further. The single pass with page hashes (266 MB/s) is 1.4 times faster than
`osslsigncode extract-data -ph` (185 MB/s) and 1.8 times faster than its `sign -ph`
(145 MB/s) on the same file, but its digest alone is slower than osslsigncode's.

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
