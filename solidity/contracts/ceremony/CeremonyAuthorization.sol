// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

/// @title CeremonyAuthorization
/// @notice The Authorization Digest of ceremony-common section 5, and the PKCE
///         construction of section 7 that carries it.
/// @dev The Platform Verifier rebuilds the digest from the payload it decoded,
///      its own ceremony version, and the chain it runs on, then binds it to
///      the evidence by one of two methods its profile fixes. Google compares
///      it against a public proof input; X and GitHub recompute the revealed
///      `code_verifier` from it. This library is the one place either
///      derivation lives, so the runtime and the chain cannot disagree.
///
///      The chain id is read here, by `digestFor`, and nowhere else. A
///      verifier cannot pass one in, so it cannot omit the term -- which would
///      make every proof replayable across chains -- or derive it differently
///      from the builders, which would reject every genuine proof.
library CeremonyAuthorization {
    /// @dev Fixed part of the preimage: 32 + 2 + 32 + 32 + 4.
    uint256 internal constant PREIMAGE_FIXED_LEN = 102;

    /// @dev Both the verifier and the challenge are this many unpadded
    ///      base64url characters.
    uint256 internal constant PKCE_LEN = 43;

    /// @dev keccak256("libid.identity.pkce"). Carries no version of its own:
    ///      the digest already binds the ceremony version, and a change to this
    ///      construction changes the proof statement, which bumps that version
    ///      (REQ-COMMON-12).
    bytes32 internal constant PKCE_DOMAIN = keccak256(bytes("libid.identity.pkce"));

    /// @dev Raised when the Authorized Transaction Data cannot be described by
    ///      the layout's four-byte length field.
    error TransactionDataTooLong(uint256 length);

    /// @notice Build the preimage of section 5, exactly.
    /// @dev `abi.encodePacked` concatenates without padding, which is what the
    ///      layout wants; every field but `transactionData` is fixed width, so
    ///      the four-byte length is what keeps the last boundary derivable.
    function preimage(
        bytes32 operationDomain,
        uint16 ceremonyVersion,
        bytes32 chain,
        bytes32 authorizationNonce,
        bytes memory transactionData
    ) internal pure returns (bytes memory) {
        // REQ-COMMON-01 says reject a value that does not fit its field. A
        // silent `uint32` truncation here would encode a length the data does
        // not have, and the Rust and TypeScript builders both refuse it.
        if (transactionData.length > type(uint32).max) {
            revert TransactionDataTooLong(transactionData.length);
        }
        return abi.encodePacked(
            operationDomain, ceremonyVersion, chain, authorizationNonce, uint32(transactionData.length), transactionData
        );
    }

    /// @notice The Authorization Digest, over an explicit chain id.
    /// @dev For the builders' vectors and for tests. A verifier uses
    ///      `digestFor`, which supplies the chain id itself.
    function digest(
        bytes32 operationDomain,
        uint16 ceremonyVersion,
        bytes32 chain,
        bytes32 authorizationNonce,
        bytes memory transactionData
    ) internal pure returns (bytes32) {
        return keccak256(preimage(operationDomain, ceremonyVersion, chain, authorizationNonce, transactionData));
    }

    /// @notice This chain's identifier, as the digest construction takes it.
    /// @dev Read from the chain and never from a payload: there is nothing in
    ///      a payload for a caller to choose here (REQ-COMMON-06C).
    function chainId() internal view returns (bytes32) {
        return keccak256(abi.encode(block.chainid));
    }

    /// @notice The Authorization Digest for THIS chain.
    /// @dev The only digest a Platform Verifier builds. It takes no chain id,
    ///      so a verifier cannot leave the chain out of the preimage or derive
    ///      it a second way.
    function digestFor(
        bytes32 operationDomain,
        uint16 ceremonyVersion,
        bytes32 authorizationNonce,
        bytes memory transactionData
    ) internal view returns (bytes32) {
        return digest(operationDomain, ceremonyVersion, chainId(), authorizationNonce, transactionData);
    }

    /// @notice `SHA256(PKCE_DOMAIN || authorizationDigest || pkceNonce)`.
    function verifierHash(bytes32 authorizationDigest, bytes32 pkceNonce) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(PKCE_DOMAIN, authorizationDigest, pkceNonce));
    }

    /// @notice `BASE64URL_NOPAD(verifierHash)` -- the 43 ASCII bytes the token
    ///         request reveals, which REQ-COMMON-15A has the Platform Verifier
    ///         recompute and compare byte for byte.
    function codeVerifier(bytes32 authorizationDigest, bytes32 pkceNonce) internal pure returns (bytes memory) {
        return _base64UrlNoPad32(verifierHash(authorizationDigest, pkceNonce));
    }

    /// @notice `BASE64URL_NOPAD(SHA256(ASCII(codeVerifier)))`.
    function codeChallenge(bytes memory verifier) internal pure returns (bytes memory) {
        return _base64UrlNoPad32(sha256(verifier));
    }

    /// @dev Encode 32 bytes as 43 unpadded base64url characters.
    ///
    /// 32 bytes are ten whole three-byte groups plus a two-byte tail, so the
    /// output length is fixed and there is no padding branch. The tail emits
    /// three characters, never four, and never an `=`.
    /// @dev `Base64.encodeURL` is the section 7 encoder exactly: the URL
    ///      alphabet, and no `=` padding, which is what RFC 4648 §5 asks for.
    ///      32 bytes encode to `PKCE_LEN` characters.
    function _base64UrlNoPad32(bytes32 value) private pure returns (bytes memory) {
        return bytes(Base64.encodeURL(bytes.concat(value)));
    }
}
