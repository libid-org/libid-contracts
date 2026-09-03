//! Typed bindings, embedded forge artifacts, and deploy/upgrade helpers for
//! the libid identity stack.
//!
//! The crate has four layers:
//!
//! - [`bindings`] — hand-written `alloy::sol!` interfaces for every contract a
//!   consumer talks to: the ceremony verification path (`NotaryService`,
//!   `CeremonyProofVerifier`), the naming system (`IdentityNames`) with its
//!   Google JWKS trust list (`IdentityJwksRoots`), and the deterministic
//!   factory. Kept in lockstep with the Solidity sources in
//!   `solidity/contracts`.
//! - [`artifacts`] — the compiled creation bytecode, link references, and
//!   method identifiers of every deployable contract, embedded at compile time
//!   ([`Artifacts::embedded`]) so deployment needs no filesystem at runtime. A
//!   directory-backed variant ([`Artifacts::from_dir`]) reads a forge `out/`
//!   tree instead.
//! - [`deploy`] — generic deploy and upgrade primitives over any alloy
//!   [`Provider`](alloy::providers::Provider): plain deploys, constructor
//!   args, ERC1967 proxies, library linking, and UUPS upgrades.
//! - [`factory`] — the deterministic-factory bootstrap: predict the canonical
//!   cross-network factory address, install it (and the keyless CREATE2
//!   deployer it hangs off) where missing, and deploy protocol proxies
//!   through it at name-derived CREATE3 addresses.
//!
//! Signing is the consumer's concern: every helper takes a provider you have
//! already wired with a wallet.

pub mod artifacts;
pub mod bindings;
pub mod deploy;
mod error;
pub mod factory;

pub use artifacts::Artifacts;
pub use error::{
    Error,
    Result,
};
