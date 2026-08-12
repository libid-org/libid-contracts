//! Bindings for the shared notary-attestation verifier. Mirrors
//! `solidity/contracts/notary/`.

/// Bindings for `notary/Notary.sol` (which implements `INotary`).
///
/// Every other contract holds a pointer to this proxy and calls
/// `verify(digest, proof)`. V1 checks a secp256k1 signature over the
/// EIP-191-prefixed digest against a single stored signer; rotation is
/// `setNotary`, and a change of proof system is a UUPS upgrade of this proxy
/// alone.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod notary_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface Notary {
            function initialize(address owner_, address notary_) external;
            function setNotary(address notary_) external;
            function notary() external view returns (address);
            /// True when `proof` is a valid notary attestation of `digest`.
            /// Answers false (never reverts) on a malformed proof.
            function verify(bytes32 digest, bytes calldata proof) external view returns (bool);

            event NotaryChanged(address indexed previousNotary, address indexed newNotary);
        }
    }
}

pub use notary_inner::Notary;
