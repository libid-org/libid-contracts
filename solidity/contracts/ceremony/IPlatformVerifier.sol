// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "./ICeremony.sol";

/// @title IPlatformVerifier
/// @notice One platform, one ceremony version, every constant that pair needs.
///
/// @dev Every platform constant lives here -- endpoints, tags, the revealed
///      layout, trust roots, parameters -- and so does the shape of the payload.
///      The Proof Verifier above holds none of them, and the Consumer above
///      that holds none either (ceremony-common section 5.1).
///
///      The verifier knows which platform it serves and which ceremony version
///      it implements, so neither travels in the payload as something to
///      trust: the platform is fixed by the route that reached this contract,
///      and the version is a constant the payload's own claim is checked
///      against.
interface IPlatformVerifier is ICeremony {
    /// @notice Decode this platform's payload, rebuild the Authorization
    ///         Digest, verify the proof, and authenticate every attestation the
    ///         profile requires.
    ///
    /// @dev The digest is rebuilt HERE, from the decoded payload, this
    ///      contract's ceremony version, and the chain it runs on. The Proof
    ///      Verifier cannot rebuild it: it does not know what the payload is.
    ///      What makes the rebuilt digest worth anything is that it is never
    ///      trusted for its content -- it is a commitment the evidence has to
    ///      match, through the revealed `code_verifier` or a public proof
    ///      input, so a caller who changes any input produces a digest no
    ///      proof opens against.
    ///
    /// @param payload This platform's encoding of one submission. Chain-native
    ///                (`abi.encode` of the verifier's payload struct): the
    ///                verifier is chain-aware, so the envelope may be. The
    ///                attestations inside it are the notary's format and stay
    ///                opaque until the Notary Service decodes them.
    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory);

    /// @notice What this verifier requires to be delivered with a payload.
    ///
    /// @dev One Notary Fee for each attestation this profile requires, and zero
    ///      where it requires none. A Consumer cannot attach a correct fee if
    ///      quoting means knowing the path's topology, so the quote covers it
    ///      (REQ-COMMON-06E). Argument-free on purpose: a price that depended
    ///      on the payload would invite forwarding less than `msg.value`, and
    ///      there is no refund path anywhere on the route.
    function quote() external view returns (uint256);

    /// @notice The identity platform this verifier serves.
    function platformId() external view returns (bytes32);
}
