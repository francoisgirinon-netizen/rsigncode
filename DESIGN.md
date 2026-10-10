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

Building blocks: `object` (PE parsing), RustCrypto (`cms`, `x509-cert`, `der`, `rsa`,
`p256`, `p384`, `sha1`, `sha2`), `p12` (PKCS#12), `cryptoki` (PKCS#11).

Signing goes through a `Signer` trait (sign a digest, return the certificate chain), with
implementations for key files, PKCS#11 and, later, cloud services.

## Large files

PE files can be close to 4 GB. Files are read through a memory map and hashed in one
pass. The patch mode of `attach-signature` writes only the bytes that change.

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
