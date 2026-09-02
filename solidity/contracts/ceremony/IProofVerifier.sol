// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "./ICeremony.sol";

/// @title IProofVerifier
/// @notice The one component every Consumer calls to verify a libID proof.
///
/// @dev Third of the four roles of ceremony-common section 5.1, counting down
///      from the Consumer. It is dispatch and nothing else: it selects the
///      Platform Verifier registered for the pair a Consumer names, forwards
///      the payload and the value to it, and forwards what comes back. It does
///      not decode the payload, holds no platform constant, and applies no
///      transaction. Only the Platform Verifier knows what the bytes are, only
///      the Consumer knows what a claim means, and only the Notary Service
///      knows whether the notary signed.
interface IProofVerifier {
    /// @notice What one verification of this pair costs, over the whole path.
    ///
    /// @dev A Consumer cannot attach a correct fee if quoting requires knowing
    ///      the path's topology, so this covers all of it: one Notary Fee per
    ///      attestation the profile requires, and zero where it requires none
    ///      (REQ-COMMON-06E).
    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);

    /// @notice Whether any version of this platform can be verified here.
    ///
    /// @dev So a Consumer can tell "no holder" from "not wired yet" without
    ///      holding a copy of the Supported Version Set.
    function verifiesPlatform(bytes32 platformId) external view returns (bool);

    /// @notice Route one payload to the Platform Verifier for this pair and
    ///         return what it authenticated.
    ///
    /// @dev `verifierVersion` selects which registered verifier answers; it is
    ///      this chain's slot number, chosen by governance here, and unrelated
    ///      to the ceremony version the verifier itself supports. `payload` is
    ///      opaque at this hop.
    function verify(bytes32 platformId, uint16 verifierVersion, bytes calldata payload)
        external
        payable
        returns (ICeremony.VerifiedClaim memory);
}
