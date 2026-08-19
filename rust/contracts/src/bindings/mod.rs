//! Hand-written `alloy::sol!` bindings, kept in lockstep with the Solidity
//! sources in `solidity/contracts`. Grouped by product area.

pub mod escrow;
pub mod factory;
pub mod identity;
pub mod login;
pub mod notary;
pub mod oidc;
pub mod proxy;
pub mod transfer;
