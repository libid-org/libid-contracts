// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Plug-in ZK identity-attestation module for the dyaka `Registry`.
///
/// One implementation per platform (X, GitHub-via-JWT, TikTok, …). The
/// verifier owns the platform-specific trust anchors (notary key, OAuth
/// client_id, expected request line) and the matching UltraHonk verifier
/// address. Registry stays small — it dispatches by `platform`, lets the
/// verifier validate the proof, and writes the resulting identity →
/// wallet mapping.
///
/// The return tuple includes a `nullifier` so the Registry can prevent a
/// stolen bearer from being used twice with different session keys —
/// TLSN-based flows must enforce this explicitly (OIDC-based flows get it
/// for free from JWT `exp` + fresh session keys).
interface IZkSessionVerifier {
    /// Verify a ZK proof + notary attestations and return the validated
    /// identity binding.
    ///
    /// `proof` is platform-specific ABI-encoded bytes — the verifier
    /// owns the codec. Returns:
    ///   * `handle`     — human-readable identity from the proof (e.g.
    ///                    X username). Registry uses it directly as the
    ///                    handle in its `(platform, handle) → wallet` map.
    ///   * `sessionKey` — Ethereum address the user is binding to.
    ///   * `expiresAt`  — proof validity deadline (unix seconds).
    ///   * `nullifier`  — domain-separated commitment to the OAuth bearer.
    ///                    Registry checks `usedBearerNullifiers[nullifier]`
    ///                    and stores it, blocking bearer-theft →
    ///                    handle-takeover when the same bearer is
    ///                    presented twice with different session keys.
    /// Returns wallet binding committed in the proof's public inputs.
    /// Registry enforces semantics: `address(0)` for `register_session_zk`,
    /// `msg.sender` for `link_identity_zk`.
    ///   * `userId`     — immutable platform user-id from the same proof
    ///                    ("" when unrevealed → handle-key fallback). Registry
    ///                    keys identity by `(platform, userId)` when non-empty.
    function verifyAndExtract(bytes calldata proof)
        external
        view
        returns (
            string memory handle,
            address sessionKey,
            address walletAddress,
            uint256 expiresAt,
            bytes32 nullifier,
            string memory userId
        );

    /// Human-readable platform name (e.g. `"api.x.com"`). Used for events
    /// and debugging.
    function platformName() external view returns (string memory);
}
