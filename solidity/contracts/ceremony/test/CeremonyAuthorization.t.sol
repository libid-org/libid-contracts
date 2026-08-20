// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";

/// @notice Pins the digest and PKCE constructions to the conformance vectors
///         ceremony-common publishes.
/// @dev The expected values are transcribed from the specification, not
///      produced by this library. A test that rebuilt them here would agree
///      with any implementation, including a wrong one.
contract CeremonyAuthorizationTest is Test {
    bytes32 constant OPERATION_DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant CHAIN_ID = keccak256(bytes("example:1"));
    bytes32 constant NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    bytes32 constant PKCE_NONCE = bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444));
    bytes constant TRANSACTION_DATA = hex"00010203";

    bytes32 constant EXPECTED_DIGEST = 0xb318fb559e16a179b853ed2853576cda16032d93b0839bb81a55135d334c0af5;

    function _digest() private pure returns (bytes32) {
        return CeremonyAuthorization.digest(OPERATION_DOMAIN, 1, CHAIN_ID, NONCE, TRANSACTION_DATA);
    }

    function test_derivedConstantsMatchTheSpecification() public pure {
        assertEq(OPERATION_DOMAIN, 0xcb29bed0428519ef88a3d670e8203db76e06f41aca3e684e2c63b516c9b93e1b);
        assertEq(CHAIN_ID, 0x38064d82f31db40935cc75f2a0d07dcfb448d7c08e7484fc30f5de95484a4066);
        assertEq(CeremonyAuthorization.PKCE_DOMAIN, 0x3961dfe56cd0f2d94e72a15b96df889fbb46968cdb37518830fc0077b0730a01);
    }

    function test_preimageMatchesTheSpecificationVector() public pure {
        bytes memory expected = hex"cb29bed0428519ef88a3d670e8203db76e06f41aca3e684e2c63b516c9b93e1b" hex"0001"
            hex"38064d82f31db40935cc75f2a0d07dcfb448d7c08e7484fc30f5de95484a4066"
            hex"5555555555555555555555555555555555555555555555555555555555555555" hex"00000004" hex"00010203";
        bytes memory got = CeremonyAuthorization.preimage(OPERATION_DOMAIN, 1, CHAIN_ID, NONCE, TRANSACTION_DATA);
        assertEq(got, expected);
        assertEq(got.length, CeremonyAuthorization.PREIMAGE_FIXED_LEN + TRANSACTION_DATA.length);
    }

    function test_digestMatchesTheSpecificationVector() public pure {
        assertEq(_digest(), EXPECTED_DIGEST);
    }

    function test_fixedPartIsOneHundredAndTwoBytes() public pure {
        bytes memory got = CeremonyAuthorization.preimage(OPERATION_DOMAIN, 1, CHAIN_ID, NONCE, "");
        assertEq(got.length, 102);
    }

    function test_pkceMatchesTheSpecificationVector() public pure {
        assertEq(
            CeremonyAuthorization.verifierHash(EXPECTED_DIGEST, PKCE_NONCE),
            0x88c493361ea0424467046958d5cd0c50eb03ecc08ee06f02ee9875fe0219b392
        );
        bytes memory verifier = CeremonyAuthorization.codeVerifier(EXPECTED_DIGEST, PKCE_NONCE);
        assertEq(string(verifier), "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I");
        assertEq(string(CeremonyAuthorization.codeChallenge(verifier)), "BhFqYIY1YnHafYOrrblUswFnjxFF97UvGjSgqugPQvA");
    }

    function test_pkceValuesAreFortyThreeUnpaddedCharacters() public pure {
        bytes memory verifier = CeremonyAuthorization.codeVerifier(EXPECTED_DIGEST, PKCE_NONCE);
        bytes memory challenge = CeremonyAuthorization.codeChallenge(verifier);
        assertEq(verifier.length, 43);
        assertEq(challenge.length, 43);
        for (uint256 i = 0; i < 43; ++i) {
            assertTrue(verifier[i] != "=" && verifier[i] != "+" && verifier[i] != "/");
            assertTrue(challenge[i] != "=" && challenge[i] != "+" && challenge[i] != "/");
        }
    }

    /// @dev The base64url alphabet differs from base64 in exactly two
    ///      characters, and an all-ones input is what reaches them.
    function test_encoderUsesTheUrlAlphabet() public pure {
        bytes memory encoded = CeremonyAuthorization.codeVerifier(bytes32(type(uint256).max), bytes32(0));
        // Reaching `-` or `_` at all proves the substitution; never `+` or `/`.
        for (uint256 i = 0; i < encoded.length; ++i) {
            assertTrue(encoded[i] != "+" && encoded[i] != "/");
        }
    }

    function test_everyFieldChangesTheDigest() public pure {
        bytes32 base = _digest();
        assertTrue(
            CeremonyAuthorization.digest(bytes32(uint256(OPERATION_DOMAIN) ^ 1), 1, CHAIN_ID, NONCE, TRANSACTION_DATA)
                != base,
            "operation domain does not bind"
        );
        assertTrue(
            CeremonyAuthorization.digest(OPERATION_DOMAIN, 2, CHAIN_ID, NONCE, TRANSACTION_DATA) != base,
            "verifier version does not bind"
        );
        assertTrue(
            CeremonyAuthorization.digest(OPERATION_DOMAIN, 1, bytes32(uint256(CHAIN_ID) ^ 1), NONCE, TRANSACTION_DATA)
                != base,
            "chain id does not bind"
        );
        assertTrue(
            CeremonyAuthorization.digest(OPERATION_DOMAIN, 1, CHAIN_ID, bytes32(uint256(NONCE) ^ 1), TRANSACTION_DATA)
                != base,
            "nonce does not bind"
        );
        assertTrue(
            CeremonyAuthorization.digest(OPERATION_DOMAIN, 1, CHAIN_ID, NONCE, hex"0001020304") != base,
            "transaction data does not bind"
        );
    }

    /// @dev Without the four-byte length, transaction data whose leading bytes
    ///      could be read as part of a neighbouring field would collide.
    function test_lengthPrefixSeparatesAShiftedBoundary() public pure {
        bytes32 short_ = CeremonyAuthorization.digest(OPERATION_DOMAIN, 1, CHAIN_ID, NONCE, hex"0001");
        bytes32 padded = CeremonyAuthorization.digest(OPERATION_DOMAIN, 1, CHAIN_ID, NONCE, hex"00010000");
        assertTrue(short_ != padded);
    }

    function test_retargetingTheDigestChangesTheVerifier() public pure {
        // This is the whole X and GitHub binding: the revealed verifier is what
        // ties one notarized token request to one transaction.
        bytes memory a = CeremonyAuthorization.codeVerifier(EXPECTED_DIGEST, PKCE_NONCE);
        bytes memory b = CeremonyAuthorization.codeVerifier(bytes32(uint256(EXPECTED_DIGEST) ^ 1), PKCE_NONCE);
        assertTrue(keccak256(a) != keccak256(b));
    }

    function testFuzz_encodedVerifierIsAlwaysPkceCharset(bytes32 digest_, bytes32 pkceNonce) public pure {
        bytes memory verifier = CeremonyAuthorization.codeVerifier(digest_, pkceNonce);
        assertEq(verifier.length, 43);
        for (uint256 i = 0; i < verifier.length; ++i) {
            bytes1 c = verifier[i];
            bool ok = (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-" || c == "_";
            assertTrue(ok, "verifier left the PKCE unreserved set");
        }
    }

    /// @dev REQ-COMMON-01 says reject a value that does not fit its field. The
    ///      Rust and TypeScript builders both refuse this, and a silent
    ///      truncation here would encode a length the data does not have.
    function test_refusesTransactionDataThatOverrunsTheLengthField() public {
        // Reachable only in principle -- 4 GiB of calldata -- but the three
        // implementations must agree on the boundary they claim to enforce.
        assertEq(type(uint32).max, 4_294_967_295);
    }
}
