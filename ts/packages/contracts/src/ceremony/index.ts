/// The ceremony profiles, TypeScript half.
///
/// What each platform's notarized sessions request, which host answers them,
/// and which bytes of the response a Platform Verifier reads. Generated from
/// `solidity/contracts/ceremony/profiles.json`, the same file `CeremonyProfile
/// .sol` and the Rust table come from, so the browser and the chain cannot
/// hold different copies.
///
/// The platform id is `keccak256` of `Profile.platform` and the authority id
/// is `keccak256` of `Session.authority`. Neither is computed here: a caller
/// that needs one already has a hasher, and this layer stays dependency-free.

export * from './profiles.js'
