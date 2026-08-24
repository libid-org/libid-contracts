// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "./ICeremony.sol";

/// @title IProofVerifier
/// @notice The one component every Consumer calls to verify a libID proof.
///
/// @dev Third of the four roles of ceremony-common section 5.1, counting down
///      from the Consumer. It selects the Platform Verifier registered for the
///      pair a submission names, recomputes the Authorization Digest, and hands
///      both down. It reads no platform constant and applies no transaction:
///      only the Consumer knows what one means, and only the Notary Service
///      knows whether the notary signed. Everything between them is dispatch.
interface IProofVerifier {
    /// @notice What one verification of this pair costs, over the whole path.
    ///
    /// @dev A Consumer cannot attach a correct fee if quoting requires knowing
    ///      the path's topology, so this covers all of it: one Notary Fee per
    ///      attestation the profile requires, and zero where it requires none
    ///      (REQ-COMMON-06E).
    function quote(bytes32 platformId, uint16 version) external view returns (uint256);

    /// @notice Whether any version of this platform can be verified here.
    ///
    /// @dev So a Consumer can tell "no holder" from "not wired yet" without
    ///      holding a copy of the Supported Version Set.
    function verifiesPlatform(bytes32 platformId) external view returns (bool);

    /// @notice Verify one submission and return what it authenticated.
    ///
    /// @dev Returns the fields of REQ-COMMON-05E and nothing but a revert on
    ///      rejection. The transaction data comes back opaque: interpreting it
    ///      belongs to the Consumer that fixed the operation domain
    ///      (REQ-COMMON-06B).
    function verify(ICeremony.Submission calldata submission) external payable returns (ICeremony.VerifiedClaim memory);
}
