# Test data

`tiny32.efi`, `tiny64.efi` and `tiny64.signed.efi` come from
[authenticode-rs](https://github.com/google/authenticode-rs)
(`authenticode/tests/testdata/`), licensed under MIT OR Apache-2.0, like rsigncode.
They are tiny PE32 / PE32+ EFI images; `tiny64.signed.efi` carries a SignTool signature.

`pe32_extra_3.signed.exe` and `pe64_aligned.signed.exe` were produced by osslsigncode from
files of the fixture builder (`tests/common/`, `cargo run --example fixtures -- <dir>`):

```
osslsigncode sign -certs c.pem -key k.pem -h sha256 -time 1556668800 -in X.exe -out X.signed.exe
```

with a throw-away self-signed certificate (`openssl req -x509 -newkey rsa:2048 -nodes`);
the private key was not kept. `pe32_extra_3.unsigned-by-ossl.exe` is the output of
`osslsigncode remove-signature` on the first one. These are tool outputs, no osslsigncode
source or test file is used.

`signtool_sha1.p7`, `signtool_sha256.p7`, `signtool_sha384.p7` and `signtool_sha512.p7` are the
PKCS #7 (without the `WIN_CERTIFICATE` header and padding) of `pe32_extra_3.exe` signed by
the real SignTool 4.00 (Windows SDK 10.0.26100, runner image `win25`) with `/fd <alg> /ph`
in the `signtool-oracle` workflow, using a throw-away self-signed certificate
(`CN=rsigncode oracle`, private key not kept). `cms.rs` compares the `SignedData` of
rsigncode with them. `cms_*.key.der` and `cms_*.cert.der` are throw-away test keys (RSA
2048, P-256, P-384) and self-signed certificates made with `openssl req -x509`.
