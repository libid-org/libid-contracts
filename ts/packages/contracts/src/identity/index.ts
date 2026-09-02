/// The wallet-agnostic identity system, TypeScript half.
///
/// Handle normalization mirrors the on-chain normalizer byte for byte, and the
/// resolvers wrap the `IdentityNames` view calls. Everything on-chain-shaped
/// comes from the generated ABIs in `../abis`, so this layer and the contracts
/// cannot drift apart silently.
///
/// Calldata for the writes is generated too, in `../calls` — `unpublish` had a
/// hand-written builder here until every write function got one.

export * from './handle.js'
export * from './handleVectors.js'
export * from './resolve.js'
