// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ICeremony
/// @notice The shapes that travel the verification path of ceremony-common
///         section 5.1: Consumer to Proof Verifier to Platform Verifier to
///         Notary Service.
///
/// @dev What a Consumer submits is NOT declared here. It is opaque bytes: the
///      Consumer names a platform and a verifier version, the Proof Verifier
///      routes on that pair, and only the Platform Verifier at the end of the
///      route knows the shape of what it decodes. Each verifier declares its
///      own payload struct, because the shapes genuinely differ -- two notarized
///      sessions and a PKCE nonce for X and GitHub, a signed token's public
///      inputs for Google -- and nothing above the verifier needs to read them.
interface ICeremony {
    /// @notice One attestation and the notary's proof that it stood behind it.
    /// @dev The Notary Service authenticates this pair by itself and accepts
    ///      no caller-supplied digest, preimage hash, or verifying key: a
    ///      caller-computed digest authenticates whatever the caller hashed,
    ///      not the bytes the Platform Verifier goes on to read
    ///      (REQ-COMMON-49).
    ///
    ///      Both halves are opaque above the Notary Service. The attested
    ///      bytes are the notary's format, not this chain's -- one notary
    ///      serves every chain, so what it attests is chain-agnostic and is
    ///      decoded by the Notary Service alone. The proof is whatever that
    ///      service accepts: a signature today, and nothing here would change
    ///      if it became a threshold of them or a zero-knowledge argument. The
    ///      envelope around the pair is what each chain encodes its own way.
    struct Attestation {
        bytes attestedData;
        bytes proof;
    }

    /// @notice What a Platform Verifier returns on acceptance, and nothing but a
    ///         rejection otherwise (REQ-COMMON-06). The Proof Verifier forwards
    ///         it unchanged.
    ///
    /// @dev A Consumer trusts these fields the way it trusts the verifier that
    ///      produced them: the verifier extracted every one from evidence it
    ///      authenticated, and the Consumer holds that verifier by an
    ///      owner-set address.
    ///
    /// @param sessionId           One ceremony, as a 32-byte handle: the
    ///                            Authorization Digest the verifier rebuilt and
    ///                            the proof opened against. Returned so the
    ///                            Consumer records the one that was actually
    ///                            used (REQ-COMMON-03) -- it is the ceremony's
    ///                            replay nullifier, and the key an indexer joins
    ///                            one ceremony's logs on.
    /// @param operationDomain     Authenticated. The Consumer MUST reject one it
    ///                            does not own, and MUST select its handler by
    ///                            this before decoding `transactionData`
    ///                            (REQ-COMMON-06A).
    /// @param transactionData     Opaque bytes; the Consumer decodes them.
    /// @param ceremonyVersion     The ceremony version the verifier supports and
    ///                            the digest binds. Not the verifier version the
    ///                            Consumer routed on: that one is this chain's
    ///                            slot number and means nothing off it.
    /// @param clientIdentifier    The exact authenticated bytes, never a digest:
    ///                            one representation across platforms lets a
    ///                            Consumer compare and display it without
    ///                            knowing which platform produced it
    ///                            (REQ-COMMON-16).
    /// @param userId              The canonical, immutable platform identifier.
    /// @param handle              RAW authenticated bytes. Normalization is the
    ///                            Consumer's derivation on its own write path,
    ///                            and a caller-supplied normalized handle or
    ///                            pre-hashed key must be refused
    ///                            (REQ-PLAT-08A, REQ-PLAT-08B).
    /// @param metadataObservedAt  The monotone metadata watermark: when the
    ///                            platform stated the identity, on the scale
    ///                            every profile shares.
    struct VerifiedClaim {
        bytes32 sessionId;
        bytes32 operationDomain;
        bytes transactionData;
        uint16 ceremonyVersion;
        bytes clientIdentifier;
        string userId;
        string handle;
        uint64 metadataObservedAt;
    }
}
