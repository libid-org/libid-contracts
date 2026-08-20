// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAttestation} from "./CeremonyAttestation.sol";
import {CeremonyFields} from "./CeremonyFields.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "./TlsNotaryVerifierBase.sol";

/// @title XPlatformVerifier — the `x/v1` profile.
///
/// @dev THE REVEALED LAYOUT IS A PROFILE DECISION. REQ-COMMON-17A requires the
///      profile to list the exact ranges a session reveals but does not fix
///      them, so `x/v1` pins them here:
///
///        token request  — two revealed sent ranges: the request line at offset
///                         0, then the whole form body. X hides no body field.
///        token response — the `"access_token":"` delimiter and its closing
///                         quote revealed; the bearer and every other byte
///                         committed.
///        identity request — the bearer committed, every other byte revealed and
///                         tiled exactly, per REQ-COMMON-35.
///        identity response — `id` and `username` with their full delimiters.
///
///      A notary emitting a different layout produces attestations this
///      verifier rejects, so the layout must be agreed before either ships.
contract XPlatformVerifier is TlsNotaryVerifierBase {
    bytes private constant GRANT_TYPE = "authorization_code";

    error WrongGrantType(bytes found);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        uint64 proofLifetime_,
        uint64 maxFutureAttestationSkew_
    ) external initializer {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_, proofLifetime_, maxFutureAttestationSkew_);
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_X;
    }

    /// @dev Both X sessions are served by the same host.
    function _tokenAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_X_API;
    }

    function _identityAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_X_API;
    }

    function _tokenRequestLine() internal pure override returns (bytes memory) {
        return "POST /2/oauth2/token ";
    }

    function _identityRequestLine() internal pure override returns (bytes memory) {
        return "GET /2/users/me ";
    }

    /// @dev REQ-PLAT-56, and X's only extra token-body check. The runtime's own
    ///      comparison runs in software the prover chooses whether to run, and
    ///      `grant_type` is the one revealed field that changes what X did with
    ///      the request: a body sending `refresh_token` while still carrying a
    ///      code, a redirect_uri and a digest-derived verifier is processed as a
    ///      refresh, returns a fresh bearer, and passes every other check — so
    ///      an application holding a user's refresh token could mint identity
    ///      proofs at arbitrary addresses indefinitely from one consent.
    function _checkTokenBody(bytes memory body) internal pure override {
        bytes memory grantType = CeremonyFields.formField(body, "grant_type");
        if (keccak256(grantType) != keccak256(GRANT_TYPE)) revert WrongGrantType(grantType);
    }

    /// @dev REQ-PLAT-31. X's `id` is a JSON string, and both fields are read by
    ///      their full `"field":"` delimiters, refusing a transcript where
    ///      either matches twice.
    function _readIdentityFields(CeremonyAttestation.DirectionBlock memory block_)
        internal
        pure
        override
        returns (string memory userId, string memory handle)
    {
        userId = string(_uniqueJsonString(block_, "id"));
        handle = string(_uniqueJsonString(block_, "username"));
    }
}
