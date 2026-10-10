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
