// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// Plug-in OIDC identity-attestation module for the `Registry`.
///
/// One implementation per OIDC provider (Google, Telegram, …). Each module
/// owns whatever trust roots its provider exposes (RSA JWKS) and the
/// matching UltraHonk verifier for that provider's JWT circuit. The
/// Registry stays small — it dispatches by `platform`, lets the verifier
/// validate the proof, and writes the resulting identity → wallet mapping
/// using the same code path that backs the TLSN-based X / GitHub flows.
interface IOidcVerifier {
    /// Verify a user proof and return the validated identity.
    ///
    /// `proof` is platform-specific bytes (the verifier decodes them).
    /// Returns:
    ///   * `handle`      — human-readable identity from the JWT (e.g. email
    ///                     for Google). The verifier guarantees this equals
    ///                     the value bound inside the circuit's public
    ///                     inputs — the Registry can use it directly as the
    ///                     handle in its `(platform, handle) → wallet` map.
    ///   * `sessionKey`  — Ethereum address the user is binding to.
    ///   * `expiresAt`   — JWT validity deadline (unix seconds).
    ///   * `userId`      — immutable platform user-id (Google JWT `sub`).
    ///                     Escrow keys on this, never the mutable handle.
    function verifyAndExtract(bytes calldata proof)
        external
        view
        returns (string memory handle, address sessionKey, uint256 expiresAt, string memory userId);

    /// Process a notary-attested rotation of this verifier's trust roots.
    /// For Google OIDC: TLS-notary attestation over the JWKS endpoint.
    function rotateRoots(bytes calldata rotationProof) external;

    /// Human-readable platform name (e.g. `"google"`). Used for events
    /// and debugging.
    function platformName() external view returns (string memory);
}
