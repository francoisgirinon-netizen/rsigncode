# SignTool compatibility

Goal: support the features of Microsoft
[SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool), with a
command line compatible with it, so that `signtool.exe` can be replaced in existing
scripts.

## Command line

A second binary, `rsigntool`, accepts the SignTool grammar:

```
rsigntool [command] [options] [file_name | ...]
```

- Options are case-insensitive and start with `/` or `-`, as in SignTool.
- Files are signed in place, several files per invocation, as in SignTool.
- Exit codes as in SignTool: 0 success, 1 failure, 2 completed with warnings.

`rsigncode` keeps the osslsigncode syntax. Both binaries use the same library. The two
grammars are not mixed in one binary: SignTool also accepts `-` options whose names clash
with osslsigncode (`-h`, `-n`, `-t`, `-p`), and its `sign` command has other semantics.

## Portability

- **Portable**: implemented on Linux, macOS and Windows.
- **Windows**: needs the Windows certificate stores, CryptoAPI/CNG or WinVerifyTrust.
  Implemented on Windows only, with a portable equivalent where one makes sense
  (PKCS#11 for key containers, a CA bundle for trust policies).

Status: `[ ]` todo, `[~]` in progress, `[x]` done.

## Global options

- [ ] `/q` quiet, `/v` verbose (portable), `/debug` (portable)

## `sign`

Digest and content
- [ ] `/fd` file digest algorithm, including `certHash` (portable)
- [ ] `/ph`, `/nph` page hashes (portable)
- [ ] `/d` description, `/du` description URL (portable)
- [ ] `/p7`, `/p7ce`, `/p7co` sign PKCS #7 content (portable)
- [ ] `/as` append a signature, i.e. nested signature (portable)
- [ ] `/ac` additional certificate (portable)

Signing certificate and key
- [ ] `/f` certificate file, PFX or certificate with `/csp` + `/kc`, `/p` password (portable for PFX)
- [ ] `/a`, `/n`, `/i`, `/r`, `/sha1`, `/u`, `/uw`, `/c` certificate selection and EKU
      filters (portable over a store abstraction; Windows stores on Windows)
- [ ] `/s`, `/sm` store name, machine store (Windows; portable mapping to a directory or PKCS#11 token)
- [ ] `/csp`, `/kc` CSP and key container (Windows; portable mapping to PKCS#11)

Timestamps
- [ ] `/t` Authenticode timestamp, `/tr` RFC 3161 timestamp, `/td` timestamp digest (portable)

Digest signing (remote or HSM signing)
- [ ] `/dg` generate the digest (`.dig`) and the unsigned PKCS #7 (`.p7u`), byte compatible
      with SignTool (portable)
- [ ] `/ds` sign the digest only (portable)
- [ ] `/di` ingest the signed digest into the file (portable)
- [ ] `/dxml` XML output for `/dg` (portable)
- [ ] `/dlib` + `/dmdf` external signing library: SignTool loads a DLL that exports
      `AuthenticodeDigestSign`. Portable equivalent: a plugin interface (shared library or
      external command) behind the same `Signer` trait; loading Windows DLLs on Windows.

## `verify`

- [ ] `/pa` default Authenticode policy (portable, with a CA bundle on non-Windows)
- [ ] `/pg` policy by GUID (Windows, WinVerifyTrust)
- [ ] `/kp` kernel-mode driver signing policy (portable rules)
- [ ] `/all`, `/ds` all signatures or signature at an index (portable)
- [ ] `/d` print description, `/ph` print and verify page hashes (portable)
- [ ] `/r` root subject, `/tw` warn if not timestamped, `/hash`, `/ms`, `/o` (portable)
- [ ] `/p7` verify PKCS #7 files (portable)
- [ ] `/c` catalog file (portable); `/a`, `/ad`, `/as`, `/ag` catalog database lookup (Windows)

## `timestamp`

- [ ] `/t`, `/tr`, `/td`, `/tp` (index), `/p7` (portable)

## `remove`

- [ ] `/s` whole signature, `/c` all certificates but the signer, `/u` unauthenticated
      attributes (portable)

## `catdb`

- [ ] `/d`, `/g`, `/r`, `/u` catalog database (Windows only: the database is a Windows service)

## Testing

Each option is checked against the real SignTool on a Windows runner: same `.dig`/`.p7u`
for `/dg`, files signed by `rsigntool` accepted by `signtool verify /pa`, and files signed
by SignTool accepted by `rsigntool verify`.
