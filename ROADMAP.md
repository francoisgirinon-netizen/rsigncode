# Roadmap

The goal is feature parity with [osslsigncode](https://github.com/mtrojnar/osslsigncode),
in pure Rust, written from the Microsoft specifications.

Status: `[ ]` todo, `[~]` in progress, `[x]` done.

## v0.1: PE files and detached signing

- [x] PE/PE32+ parsing (headers, sections, certificate table), checksum
- [x] Authenticode digest (SHA-1, SHA-256, SHA-384, SHA-512), with the 8-byte padding of
      unsigned files that SignTool uses
- [ ] Page hashes (`-ph`), SHA-1 and SHA-256
- [ ] `SpcIndirectDataContent`, `SpcPeImageData`, `SpcSpOpusInfo` (`-n`, `-i`),
      statement type (`-comm`)
- [ ] CMS `SignedData` with RSA (PKCS#1 v1.5) and ECDSA keys
- [ ] Keys and certificates: PEM/DER files (`-certs`, `-key`), PKCS#12 (`-pkcs12`),
      passwords (`-pass`, `-readpass`, `-askpass`), additional certificates (`-ac`)
- [ ] Keys in a HSM or token: PKCS#11 (`-pkcs11module`, `-pkcs11cert`, `-login`)
- [ ] Insert the signature: padding, `WIN_CERTIFICATE`, certificate table entry, checksum
- [ ] Detached signing: `extract-data`, `sign` on the extracted data, `attach-signature`
- [ ] Patch mode: write only the bytes that change (checksum, certificate table entry,
      padding, signature) instead of rewriting the whole file
- [ ] `remove-signature`, `extract-signature` (`-pem`)
- [ ] `verify`: digests, page hashes, certificate chain (`-CAfile`, `-CRLfile`,
      `-ignore-crl`, `-ignore-cdp`, `-time`), `-require-leaf-hash`
- [ ] Files up to the 4 GB limit of the PE format, without loading them twice in memory

## v0.2: timestamps and nested signatures

- [ ] Authenticode timestamps (`-t`) and RFC 3161 timestamps (`-ts`), proxies (`-p`),
      HTTPS options (`-HTTPS-CAfile`, `-HTTPS-CRLfile`, `-noverifypeer`)
- [ ] Built-in TSA for testing (`-TSA-certs`, `-TSA-key`, `-TSA-time`)
- [ ] Timestamp verification (`-TSA-CAfile`, `-TSA-CRLfile`, `-ignore-timestamp`)
- [ ] Nested signatures (`-nest`), `-index` for `add` and `verify`
- [ ] `add`: timestamp, `-addUnauthenticatedBlob` (`-blobFile`)
- [ ] Signing time (`-time`), `-jp` (Java permissions, legacy)

## v0.3: other file formats

- [ ] CAB
- [ ] MSI (compound file), `MsiDigitalSignatureEx` (`-add-msi-dse`)
- [ ] APPX, MSIX, APPXBUNDLE, MSIXBUNDLE
- [ ] Catalog files (CAT)
- [ ] Scripts: PowerShell (`.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.psc1`, `.cdxml`),
      MOF, JScript

## Later

- [ ] Cloud key services (Azure Key Vault and Trusted Signing, AWS KMS, Google Cloud KMS)
      through the same signer interface as files and PKCS#11
- [ ] Library API stable enough for other tools

Not planned: OpenSSL engines and providers (`-engine`, `-engineCtrl`, `-provider`,
`-nolegacy`) and the legacy SPC/PVK formats, which only make sense with OpenSSL.
