// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyFields} from "./CeremonyFields.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "./TlsNotaryVerifierBase.sol";

/// @title GitHubPlatformVerifier — the `github/v1` profile.
///
/// @notice The same relation X states, from a confidential client.
///
/// @dev GitHub uses a confidential client, so the exchange cannot run in the
///      browser and the deployment's Token-Exchange Service is the notarized
///      party for that session. On chain that changes nothing: this verifier
///      sees two attestations and one proof, exactly as X does. It differs in
///      four constants and two reads.
///
///      TWO AUTHORITIES, NOT ONE. `github.com` serves the exchange and
///      `api.github.com` serves the identity read, so an authority is per
///      SESSION here. A profile pinning one authority would accept an identity
///      attestation from the exchange host, or the reverse.
///
///      NO `grant_type` TO COMPARE. Section 6.2 lists five fields and that is
///      not among them, so REQ-PLAT-56 has no GitHub counterpart and this
///      profile adds no extra token-body check.
///
///      THE REVEALED LAYOUT IS A PROFILE DECISION, as it is for X:
///
///        token exchange — the request line at offset 0, then the revealed body
///                         PREFIX. `client_secret` is ordered last per
///                         REQ-COMMON-22 and committed, so the prefix ends
///                         where it begins and every field a verifier reads
///                         sits inside it.
///        token response — the `"access_token":"` delimiter and closing quote
///                         revealed; the bearer and everything else committed.
///        identity request — the bearer committed, every other byte revealed
///                         and tiled exactly.
///        identity response — `id` and `login` with their full delimiters.
///
///      The three identity-session checks do NOT reach the exchange's body
///      credential: REQ-COMMON-43 forbids demanding a CRLF-framed
///      `authorization: Bearer ` around a form-body range, which would reject
///      every valid exchange. The secret is protected instead by being ordered
///      last with a delimiter-free charset, which REQ-PLAT-35 makes a
///      deployment obligation — GitHub secrets are hex, so it holds by
///      inspection.
contract GitHubPlatformVerifier is TlsNotaryVerifierBase {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        bytes32 honkVerifierCodehash_,
        uint64 proofLifetime_,
        uint64 maxFutureAttestationSkew_,
        uint64 futureObservationAllowance_
    ) external initializer {
        __PlatformVerifierBase_init(
            owner_,
            notary_,
            honkVerifier_,
            honkVerifierCodehash_,
            proofLifetime_,
            maxFutureAttestationSkew_,
            futureObservationAllowance_
        );
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GITHUB;
    }

    /// @dev The exchange host.
    function _tokenAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_GITHUB;
    }

    /// @dev The API host. Deliberately not the same as above.
    function _identityAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_GITHUB_API;
    }

    /// @dev GitHub commits its `client_secret`, ordered last under
    ///      REQ-COMMON-22, so exactly one committed range reaches the end.
    function _tokenSentCommitments() internal pure override returns (uint256) {
        return 1;
    }

    function _tokenRequestLine() internal pure override returns (bytes memory) {
        return "POST /login/oauth/access_token ";
    }

    function _identityRequestLine() internal pure override returns (bytes memory) {
        return "GET /user ";
    }

    /// @dev REQ-PLAT-51. GitHub's `id` is a BARE integer, so it is read by the
    ///      integer template with its terminator pinned to `,` or `}` and no
    ///      other byte: the terminator is what proves the revealed digits are
    ///      the whole number rather than a prefix of a longer one, and JSON
    ///      member order does not say which of the two closes it.
    ///
    ///      The handle field is `login`, not `username`.
    function _identityFields()
        internal
        pure
        override
        returns (string memory idField, IdShape idShape, string memory handleField)
    {
        return ("id", IdShape.JsonInteger, "login");
    }
}
