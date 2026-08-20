// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CeremonyProfile
/// @notice The tags a Platform Verifier pins, and the governance-owned
///         protocol parameters it reads.
///
/// @dev THE NAMESPACED STRINGS ARE OURS, NOT THE SPECIFICATION'S.
///      ceremony-common fixes exactly one literal: `libid.identity.pkce`, in
///      section 7. Every other libID-namespaced string -- `formatTag`
///      (REQ-COMMON-53), `operationTag` and the platform name
///      (REQ-COMMON-55), and each Consumer's operation domain
///      (REQ-COMMON-01A) -- is required to exist and required to be pinned,
///      but its bytes are left to the profile author.
///
///      So these are a cross-implementation agreement, not a reading of the
///      specification. A notary emitting one string and a verifier pinning
///      another derives a key nobody trusts and rejects every genuine
///      attestation, with no error that says why. `libid-rs` carries the same
///      strings in `crates/libid-ceremony/src/profile.rs`.
library CeremonyProfile {
    // --- Attestation tags ---------------------------------------------------

    /// @dev Names the attested-data layout and its version (REQ-COMMON-53). A
    ///      change to the field list, to a field's width, or to a field's
    ///      meaning takes a new version string rather than another field.
    bytes32 internal constant FORMAT_TAG = keccak256(bytes("libid.attestation.v1"));

    /// @dev Which session of the ceremony an attestation covers
    ///      (REQ-COMMON-55). One ceremony notarizes more than one session, and
    ///      two attestations differing only in that would be interchangeable.
    bytes32 internal constant TOKEN_SESSION_TAG = keccak256(bytes("libid.ceremony.session.token.v1"));
    bytes32 internal constant IDENTITY_SESSION_TAG = keccak256(bytes("libid.ceremony.session.identity.v1"));

    // --- Platform identifiers -----------------------------------------------

    bytes32 internal constant PLATFORM_GOOGLE = keccak256(bytes("google"));
    bytes32 internal constant PLATFORM_X = keccak256(bytes("x"));
    bytes32 internal constant PLATFORM_GITHUB = keccak256(bytes("github"));

    // --- Authorities --------------------------------------------------------

    /// @dev The lowercase ASCII TLS server name, with no trailing dot, that the
    ///      notary authenticated. It reaches the verifier as `authorityId` and
    ///      never as a transcript range: the transcript holds the authority
    ///      only in a prover-composed `Host` header, which says nothing about
    ///      which server answered (REQ-COMMON-21, REQ-COMMON-56).
    ///
    ///      GitHub's two sessions have two different authorities.
    bytes32 internal constant AUTHORITY_X_API = keccak256(bytes("api.x.com"));
    bytes32 internal constant AUTHORITY_GITHUB = keccak256(bytes("github.com"));
    bytes32 internal constant AUTHORITY_GITHUB_API = keccak256(bytes("api.github.com"));

    // --- Launch profile shape ------------------------------------------------

    /// @dev Launch profiles are `google/v1`, `x/v1` and `github/v1`
    ///      (REQ-PLAT-01).
    uint16 internal constant LAUNCH_VERSION = 1;

    /// @dev Derived from the session list the profile fixes, never stated
    ///      beside it (REQ-COMMON-41). Google verifies none and pays nothing;
    ///      X and GitHub verify two each, so one submission pays two fees.
    function attestationCount(bytes32 platformId) internal pure returns (uint8) {
        if (platformId == PLATFORM_GOOGLE) return 0;
        if (platformId == PLATFORM_X || platformId == PLATFORM_GITHUB) return 2;
        revert UnknownPlatform(platformId);
    }

    error UnknownPlatform(bytes32 platformId);

    // --- Protocol parameters -------------------------------------------------

    /// @dev Governance-owned seconds, read where they are enforced. The
    ///      Platform Verifier reads the current value when it verifies and MUST
    ///      NOT accept a caller-supplied substitute (REQ-PARAM-02). These are
    ///      the launch values; a deployment stores and updates them.
    uint64 internal constant LAUNCH_PROOF_LIFETIME_X = 3600;
    uint64 internal constant LAUNCH_PROOF_LIFETIME_GITHUB = 3600;
    uint64 internal constant LAUNCH_MAX_FUTURE_ATTESTATION_SKEW = 300;
}
