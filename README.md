# rsigncode

Authenticode signing and verification for Windows files (PE, and later MSI, CAB, APPX,
catalogs and scripts), in pure Rust, on Linux, macOS and Windows.

The goal is feature parity with osslsigncode. Nothing is implemented yet: see
[ROADMAP.md](ROADMAP.md) and [DESIGN.md](DESIGN.md).

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
