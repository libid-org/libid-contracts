//! The off-chain half of handle normalization.
//!
//! `handle` is hand written and mirrors `contracts/identity/HandleNormalizer.sol`
//! byte for byte; `handle_vectors` is generated from
//! `contracts/identity/handles.json` by `scripts/regen-identity-handles.py`.
//! Solidity, Rust and TypeScript each run the same vector table, so a
//! difference between the languages fails a test instead of writing a key the
//! chain never wrote.

#![deny(warnings)]
#![deny(missing_docs)]

pub mod handle;

#[rustfmt::skip]
pub mod handle_vectors;

pub use handle::{
    normalize,
    HandleError,
    Rules,
};
