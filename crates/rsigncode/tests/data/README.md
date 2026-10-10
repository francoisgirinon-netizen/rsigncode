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
