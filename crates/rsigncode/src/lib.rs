//! Authenticode signing and verification in pure Rust.
//!
//! The goal is feature parity with osslsigncode, written from the Microsoft
//! specifications. See `ROADMAP.md` and `DESIGN.md` at the repository root.

pub mod hash;
pub mod pe;
pub mod spc;
