# rsigncode

[![CI](https://github.com/francoisgirinon-netizen/rsigncode/actions/workflows/ci.yml/badge.svg)](https://github.com/francoisgirinon-netizen/rsigncode/actions/workflows/ci.yml)
[![Security](https://github.com/francoisgirinon-netizen/rsigncode/actions/workflows/security.yml/badge.svg)](https://github.com/francoisgirinon-netizen/rsigncode/actions/workflows/security.yml)
[![SignTool oracle](https://github.com/francoisgirinon-netizen/rsigncode/actions/workflows/signtool-oracle.yml/badge.svg)](https://github.com/francoisgirinon-netizen/rsigncode/actions/workflows/signtool-oracle.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-yellow.svg)](https://www.conventionalcommits.org/en/v1.0.0/)

Authenticode signing and verification for Windows files (PE, and later MSI, CAB, APPX,
catalogs and scripts), in pure Rust, on Linux, macOS and Windows.

The goal is feature parity with osslsigncode, and later a SignTool compatible command
line ([SIGNTOOL.md](SIGNTOOL.md)).

## Status

Early development. Implemented in the library:

- PE/PE32+ parsing and checksum.
- Authenticode digest (SHA-1, SHA-256, SHA-384, SHA-512) and page hashes, computed in one
  multi-threaded pass, checked against osslsigncode.

The `rsigncode` command line is a skeleton: its commands do not sign or verify yet. See
[ROADMAP.md](ROADMAP.md) and [DESIGN.md](DESIGN.md).

## Testing

```sh
cargo test --workspace
cargo test --workspace --no-default-features --features pure-rust
```

Two hashing backends: aws-lc (default, needs a C compiler, NASM on Windows) and pure Rust
(RustCrypto). CI runs both on Linux, macOS and Windows. A Windows job compares the results
with the real SignTool and imagehlp (`SignTool oracle`). Dependencies are checked for
advisories, licenses and sources with cargo-deny (`Security`).

At least 95 % of the lines must be covered by the tests (`coverage` job, `cargo llvm-cov`).

The settings of the `main` branch are in [.github/rulesets/main.json](.github/rulesets/main.json):
linear history, pull request with rebase merge only, and the CI checks above. GitHub needs a
public repository (or a paid plan) to apply them, with
`gh api -X POST repos/{owner}/{repo}/rulesets --input .github/rulesets/main.json`.

Release binaries (static Linux musl, Windows, macOS) are built by the `Release` workflow
when a `vX.Y.Z` tag is pushed.

## Contributing

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
(`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `chore:`, `ci:`...). Enable the
hooks, which check the commit message, `cargo fmt` and `cargo clippy`:

```sh
git config core.hooksPath .githooks
```

The same checks run in CI.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
