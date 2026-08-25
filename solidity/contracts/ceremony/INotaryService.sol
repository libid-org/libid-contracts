// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAttestation} from "./CeremonyAttestation.sol";

/// @title INotaryService
/// @notice The bottom of the verification path of ceremony-common section 5.1.
/// @dev It answers one question -- is this attestation authentic -- and knows
///      nothing else. Which ranges a profile expects and what their bytes must
///      contain belong to the Platform Verifier (REQ-COMMON-51); deciding
///      anything profile-specific here is forbidden outright (REQ-COMMON-33).
interface INotaryService {
    /// @notice Authenticate one attestation, and charge one fee for doing it.
    ///
    /// @dev Takes the attested data and its signature and derives the
    ///      verification key from that pair alone. It accepts no digest,
    ///      preimage hash, or verifying key from its caller: a caller-computed
    ///      digest authenticates whatever the caller hashed, which need not be
    ///      the bytes the Platform Verifier goes on to read (REQ-COMMON-49).
    ///
    ///      Rejection is a revert, and this returns nothing. REQ-COMMON-42
    ///      requires the fees of one submission to take effect together or not
    ///      at all, and to leave nothing delivered once the submission is
    ///      rejected -- reverting gives both by construction, with no refund
    ///      path to get wrong. Returning a boolean would offer a second way to
    ///      say "rejected" that keeps the fee and lets a caller miss it.
    ///
    ///      It returns the decoded record rather than a bare accept, because
    ///      the format is this service's to know: REQ-COMMON-18 has a profile
    ///      pin the exact Notary Service AND the attestation format it accepts,
    ///      as a pair, so pinning the service is what pins the format. A caller
    ///      that decoded the bytes itself would be holding the second half of
    ///      that pair independently, free to drift from the first.
    ///
    ///      It also removes a shape rather than a bug. With `void` here, the
    ///      decoder is reachable without the signature check -- nothing but two
    ///      statements staying adjacent keeps "authenticate, then read" true.
    ///      Handed back, the fields cannot be reached without paying for the
    ///      check that vouches for them.
    ///
    /// @param attestedData The exact bytes of ceremony-common section 9.1.
    /// @param signature    The notary signature over `keccak256(attestedData)`.
    /// @return attested    Those bytes decoded, once the key has vouched.
    function verify(bytes calldata attestedData, bytes calldata signature)
        external
        payable
        returns (CeremonyAttestation.AttestedData memory attested);

    /// @notice The fee one verification currently costs, in the chain's native
    ///         asset.
    /// @dev Readable before a submission is constructed, because a fee that
    ///      cannot be read cannot be bounded (REQ-COMMON-34D). It varies with
    ///      nothing -- not the attested content, not the Transaction Author,
    ///      the Fee Payer or the Transaction Submitter, because a fee that
    ///      varies by principal or content is selective censorship of a
    ///      permissionless service (REQ-COMMON-34C).
    function fee() external view returns (uint256);

    /// @notice Whether a key is currently one the service trusts.
    function isTrustedNotary(address key) external view returns (bool);
}
