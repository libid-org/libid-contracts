//! The libID ceremony profiles.
//!
//! What each platform's notarized sessions request, which host answers them,
//! and which bytes of the response a Platform Verifier reads. The values are
//! generated from `solidity/contracts/ceremony/profiles.json`, the same file
//! `CeremonyProfile.sol` is generated from, so a prover and the chain cannot
//! hold different copies.
//!
//! # What is not here
//!
//! Ids. `platformId` is `keccak256` of [`Profile::platform`] and `authorityId`
//! is `keccak256` of [`Session::authority`], and this crate hashes neither: a
//! caller that needs an id already has a hasher, and a crate that pulled one
//! in to precompute six values would make every consumer carry it.
//!
//! Behaviour. Which ranges a session reveals, how a handle normalizes, what a
//! verifier checks -- all hand written where they belong. This is the table
//! those read.

mod profiles;

pub use profiles::*;
