// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title INotary — the one notary check every contract shares.
///
/// @notice A consumer computes its own digest (its domain separation — chain
///         id, its own address, operation tags — stays its own concern) and
///         asks this contract whether `proof` attests to it. Today a proof is
///         a secp256k1 signature over the EIP-191-prefixed digest; a future
///         implementation may accept a different kind of proof entirely, which
///         is why the parameter is opaque bytes rather than a signature type.
interface INotary {
    /// @notice True when `proof` is a valid notary attestation of `digest`.
    /// @param digest The consumer-computed digest being attested (pre-EIP-191;
    ///        the implementation owns whatever wrapping its proof kind needs).
    /// @param proof  Opaque attestation bytes. V1: a 65-byte ECDSA signature.
    /// @dev MUST return false rather than revert on a malformed `proof`, so a
    ///      consumer can surface its own error.
    function verify(bytes32 digest, bytes calldata proof) external view returns (bool);

    /// @notice The current notary signer. Observability for V1's key scheme; a
    ///         proof-based implementation may return the zero address.
    function notary() external view returns (address);
}
