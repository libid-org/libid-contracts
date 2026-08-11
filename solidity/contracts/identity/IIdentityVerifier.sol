// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice What a platform's proof yields once it verifies.
///
/// @param userId     The platform's immutable account id. A rename never
///                   changes it, so it is what a binding is anchored on.
/// @param handle     The handle exactly as proved. The identity contract
///                   normalizes it; a verifier must not.
/// @param target     The address the proof was made out to. The identity
///                   contract requires this to be `msg.sender`, which is what
///                   stops a proof read from the mempool from being spent by
///                   somebody else.
/// @param observedAt When the platform stated these facts. This is a provider
///                   timestamp, not a chain timestamp: Google uses the signed
///                   token, X and GitHub use the notarized response. It orders
///                   two proofs of the same handle, so a proof held back cannot
///                   undo a newer one.
struct IdentityClaim {
    string userId;
    string handle;
    address target;
    uint64 observedAt;
}

/// @notice One platform's proof format.
///
/// @dev **A verifier is the contract its proofs are made out to.** The
///      attestation or the circuit commits which contract will check it, and a
///      verifier checks that commitment against itself — so a proof minted for
///      any other deployment, including another product speaking the same
///      protocol to the same platform, does not verify here.
///
///      That is what keeps the naming system standing on its own. A verifier
///      that read another product's contract for its keys, its response shape
///      or its trust list would tie a naming release to that product's release,
///      put its address inside every name binding, and leave the naming system
///      undeployable by anyone who does not run it. Where two systems prove the
///      same thing about the same platform, they duplicate the pipeline: the
///      cost is a second attestation, and the alternative costs the
///      independence.
///
///      A verifier must also pin the platform it speaks for. Proof formats are
///      shared across platforms — one notary serves several — so a verifier
///      that reads the platform out of the proof and does not check it will
///      accept a neighbour's proof and bind it under the wrong name.
interface IIdentityVerifier {
    /// @notice Verify a proof and return what it states.
    /// @dev Reverts when the proof does not verify. Never returns a zero
    ///      target: a claim naming nobody is one anybody could redirect.
    function verify(bytes calldata proof) external view returns (IdentityClaim memory claim);

    /// @notice The platform this verifier speaks for, for events and debugging.
    function platformName() external view returns (string memory);
}
