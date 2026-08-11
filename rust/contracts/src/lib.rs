//! Typed bindings, embedded forge artifacts, and deploy/upgrade helpers for
//! the libid contract stack.
//!
//! The crate has three layers:
//!
//! - [`bindings`] — hand-written `alloy::sol!` interfaces for every contract a
//!   consumer talks to: the login stack (`Registry`, `WebWallet`,
//!   `WalletFactory`, verifiers), the Bank diamond, and the identity-names
//!   stack. Kept in lockstep with the Solidity sources in `solidity/contracts`.
//! - [`artifacts`] — the compiled creation bytecode, link references, and
//!   method identifiers of every deployable contract, embedded at compile time
//!   ([`Artifacts::embedded`]) so deployment needs no filesystem at runtime. A
//!   directory-backed variant ([`Artifacts::from_dir`]) reads a forge `out/`
//!   tree instead.
//! - [`deploy`] / [`diamond`] — generic deploy and upgrade primitives over any
//!   alloy [`Provider`](alloy::providers::Provider): plain deploys, constructor
//!   args, ERC1967 proxies, library linking, UUPS upgrades, and the Bank
//!   EIP-2535 diamond deploy/facet-replace flows.
//!
//! Signing is the consumer's concern: every helper takes a provider you have
//! already wired with a wallet.

pub mod artifacts;
pub mod bindings;
pub mod deploy;
pub mod diamond;
mod error;

pub use artifacts::Artifacts;
pub use error::{
    Error,
    Result,
};
