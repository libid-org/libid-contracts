// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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
    /// @param attestedData The exact bytes of ceremony-common section 9.1.
    /// @param signature    The notary signature over `keccak256(attestedData)`.
    function verify(bytes calldata attestedData, bytes calldata signature) external payable;

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
