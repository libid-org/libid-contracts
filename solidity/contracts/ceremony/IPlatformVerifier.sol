// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "./ICeremony.sol";

/// @title IPlatformVerifier
/// @notice One platform, one version, every constant that platform needs.
///
/// @dev Every platform constant lives here -- endpoints, tags, the revealed
///      layout, trust roots, parameters. The Proof Verifier above holds none of
///      them, and the Consumer above that holds none either
///      (ceremony-common section 5.1).
interface IPlatformVerifier is ICeremony {
    /// @notice Check this platform's fields, verify the proof, and authenticate
    ///         every attestation the profile requires.
    ///
    /// @dev The digest is passed down, not rebuilt. REQ-COMMON-46 has the Proof
    ///      Verifier recompute it and forward it, and has the Platform Verifier
    ///      take it from that forwarded value and from nothing else -- a
    ///      verifier left to rebuild it would compare against a digest the
    ///      caller could choose.
    ///
    /// @param authorizationDigest Recomputed one hop above, under REQ-COMMON-02.
    /// @param submission          The whole submission, forwarded unchanged.
    function verify(bytes32 authorizationDigest, Submission calldata submission)
        external
        payable
        returns (PlatformFields memory fields);

    /// @notice What this verifier requires to be delivered with a submission.
    ///
    /// @dev One Notary Fee for each attestation this profile requires, and zero
    ///      where it requires none. A Consumer cannot attach a correct fee if
    ///      quoting means knowing the path's topology, so the quote covers it
    ///      (REQ-COMMON-06E).
    function quote() external view returns (uint256);

    /// @notice The identity platform this verifier serves.
    function platformId() external view returns (bytes32);
}
