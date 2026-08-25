/// The wallet-agnostic identity system, TypeScript half.
///
/// Handle normalization mirrors the on-chain normalizer byte for byte, the
/// bind encoders produce exactly what the verifiers decode, and the resolvers
/// wrap the `IdentityNames` view calls. Everything on-chain-shaped comes from
/// the generated ABIs in `../abis`, so this layer and the contracts cannot
/// drift apart silently.

export * from './calls.js'
export * from './handle.js'
export * from './handleVectors.js'
export * from './resolve.js'
