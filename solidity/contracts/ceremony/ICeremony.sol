// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ICeremony
/// @notice The shapes that travel the verification path of ceremony-common
///         section 5.1: Consumer to Proof Verifier to Platform Verifier to
///         Notary Service.
interface ICeremony {
    /// @notice One attestation and the notary signature over it.
    /// @dev The Notary Service derives the verification key from this pair
    ///      alone and accepts no caller-supplied digest, preimage hash, or
    ///      verifying key: a caller-computed digest authenticates whatever the
    ///      caller hashed, not the bytes the Platform Verifier goes on to read
    ///      (REQ-COMMON-49).
    struct Attestation {
        bytes attestedData;
        bytes signature;
    }

    /// @notice What a Consumer submits.
    ///
    /// @dev It carries no Chain ID. The Proof Verifier takes that from the
    ///      chain it observes and never from the submission, so there is
    ///      nothing here for a caller to choose (REQ-COMMON-06C).
    ///
    /// @param platformId          Selects the Platform Verifier, with `version`.
    /// @param version             The Platform Verifier Version. Dispatch reads
    ///                            it here, so it cannot disagree with the
    ///                            version the digest commits.
    /// @param operationDomain     Authenticated by digest recomputation rather
    ///                            than trusted; the Proof Verifier returns it
    ///                            and the Consumer decides whether it owns it.
    /// @param authorizationNonce  Makes the digest unique, and therefore its
    ///                            own replay nullifier.
    /// @param transactionData     Opaque here. Only the Consumer may decode it
    ///                            (REQ-COMMON-06B).
    /// @param pkceNonce           Carried for a profile that binds the digest
    ///                            through PKCE; empty for one that does not.
    /// @param proof               Verified under the artifact governance
    ///                            selected, never one the caller names.
    /// @param publicInputs        The proof's public inputs.
    /// @param attestations        Exactly the list the profile requires: two
    ///                            for X and GitHub, none for Google.
    /// @param clientIdentifier    Google only: the `aud` bytes, which the
    ///                            verifier authenticates by hashing them
    ///                            against a public proof input. X and GitHub
    ///                            read theirs from a revealed range instead, so
    ///                            supplying it here would be a duplicate the
    ///                            caller controls (REQ-COMMON-52).
    struct Submission {
        bytes32 platformId;
        uint16 version;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        bytes32 pkceNonce;
        bytes proof;
        bytes32[] publicInputs;
        Attestation[] attestations;
        bytes clientIdentifier;
    }

    /// @notice What a Platform Verifier returns on acceptance.
    ///
    /// @dev An authenticated `userId`, handle and observation time are what the
    ///      ceremony exists to produce, and the Consumer has no other
    ///      authenticated source for them (REQ-COMMON-05E). The Proof Verifier
    ///      adds the operation domain and transaction data to make the
    ///      `VerifiedClaim` below.
    ///
    /// @param clientIdentifier   The exact authenticated bytes, never a digest.
    /// @param userId             The canonical, immutable platform identifier.
    /// @param handle             RAW authenticated bytes; the Consumer
    ///                           normalizes on its own write path.
    /// @param metadataObservedAt The monotone metadata watermark.
    struct PlatformFields {
        bytes clientIdentifier;
        string userId;
        string handle;
        uint64 metadataObservedAt;
    }

    /// @notice What the Proof Verifier returns on acceptance, and nothing but a
    ///         rejection otherwise (REQ-COMMON-06).
    ///
    /// @param operationDomain    Authenticated. The Consumer MUST reject one it
    ///                           does not own, and MUST select its handler by
    ///                           this before decoding `transactionData`
    ///                           (REQ-COMMON-06A).
    /// @param transactionData    Still opaque; the Consumer decodes it.
    /// @param clientIdentifier   The exact authenticated bytes, never a digest:
    ///                           one representation across platforms lets a
    ///                           Consumer compare and display it without
    ///                           knowing which platform produced it
    ///                           (REQ-COMMON-16).
    /// @param userId             The canonical, immutable platform identifier.
    /// @param handle             RAW authenticated bytes. Normalization is the
    ///                           Consumer's derivation on its own write path,
    ///                           and a caller-supplied normalized handle or
    ///                           pre-hashed key must be refused
    ///                           (REQ-PLAT-08A, REQ-PLAT-08B).
    /// @param metadataObservedAt The monotone metadata watermark.
    struct VerifiedClaim {
        bytes32 operationDomain;
        bytes transactionData;
        bytes clientIdentifier;
        string userId;
        string handle;
        uint64 metadataObservedAt;
    }
}
