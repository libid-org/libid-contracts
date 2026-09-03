// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {XZkVerifier} from "../XZkVerifier.sol";
import {XZkVerifierBindingsTest} from "./XZkVerifierBindings.t.sol";

/// Multi-app `client_id` allowlist on XZkVerifier.
///
/// The security property under test is FAIL-CLOSED: an empty allowlist denies
/// every client_id. "Not configured yet" must never be read as "allow everyone",
/// otherwise an unseeded deploy or the removal of the last entry would silently
/// drop the app binding. Permissive mode exists, but only as the explicit
/// `openClientIds` flag.
///
/// Inherits the bindings test for its fixtures and attestation builders.
contract XZkVerifierAllowlistTest is XZkVerifierBindingsTest {
    address constant WALLET = address(0x1111);
    address constant SESSION = address(0x5E5510);
    bytes32 constant BEARER_HASH = bytes32(uint256(0xBEEF));
    bytes32 constant NULLIFIER = bytes32(uint256(0xC0FFEE));

    bytes constant OTHER_CLIENT_ID = bytes("second-app-id-456");

    /// Payload whose /token body carries `client_id=<clientId>`, notary-signed
    /// over that exact body. Mirrors _buildTokenAttest but with a caller-chosen
    /// client_id so a non-allowlisted app can be exercised.
    function _payloadWithClientId(bytes memory clientId) internal view returns (bytes memory) {
        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(BEARER_HASH, uint64(block.timestamp));
        tokenAttest.sentRevealed = abi.encodePacked("grant_type=authorization_code&client_id=", clientId, "&code=xyz");
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(verifier),
                keccak256(bytes(PLATFORM)),
                keccak256("XZkVerifier.token.v1"),
                tokenAttest.bearerHash,
                uint256(tokenAttest.bearerRangeStart),
                uint256(tokenAttest.bearerRangeEnd),
                keccak256(tokenAttest.sentRevealed),
                uint256(tokenAttest.timestamp)
            )
        );
        tokenAttest.notarySignature = _sign(NOTARY_PK, digest);

        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(BEARER_HASH, "alice", SESSION, uint64(block.timestamp));
        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(BEARER_HASH, BEARER_HASH, NULLIFIER, WALLET, SESSION),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        return abi.encode(p);
    }

    function _verify(bytes memory payload) internal {
        vm.prank(WALLET);
        verifier.verifyAndExtract(payload);
    }

    // ─── Seeding ─────────────────────────────────────────────────────

    /// initialize() seeds the deploying app, so an unchanged deploy keeps working.
    function test_initialize_seedsDeployingClientId() public view {
        assertEq(verifier.clientIdCount(), 1);
        assertTrue(verifier.isClientIdAllowed(keccak256(X_CLIENT_ID)));
        assertEq(verifier.clientIdAt(0), X_CLIENT_ID);
        assertFalse(verifier.openClientIds(), "must not start permissive");
    }

    // ─── Fail-closed ─────────────────────────────────────────────────

    /// THE fail-closed property: with the allowlist emptied, every client_id is
    /// rejected — including the one that worked a moment ago. A regression that
    /// treated "empty" as "allow all" would make this pass verification instead.
    function test_emptyAllowlist_deniesEveryClientId() public {
        vm.prank(OWNER);
        verifier.removeClientId(X_CLIENT_ID);
        assertEq(verifier.clientIdCount(), 0);

        vm.expectRevert(XZkVerifier.ClientIdMismatch.selector);
        _verify(_payloadWithClientId(X_CLIENT_ID));

        vm.expectRevert(XZkVerifier.ClientIdMismatch.selector);
        _verify(_payloadWithClientId(OTHER_CLIENT_ID));
    }

    function test_unlistedClientId_rejected() public {
        vm.expectRevert(XZkVerifier.ClientIdMismatch.selector);
        _verify(_payloadWithClientId(OTHER_CLIENT_ID));
    }

    // ─── Multi-app ───────────────────────────────────────────────────

    function test_addClientId_admitsSecondApp_bothWork() public {
        vm.prank(OWNER);
        verifier.addClientId(OTHER_CLIENT_ID);

        assertEq(verifier.clientIdCount(), 2);
        _verify(_payloadWithClientId(OTHER_CLIENT_ID));
        _verify(_payloadWithClientId(X_CLIENT_ID));
    }

    function test_removeClientId_revokesOnlyThatApp() public {
        vm.startPrank(OWNER);
        verifier.addClientId(OTHER_CLIENT_ID);
        verifier.removeClientId(X_CLIENT_ID);
        vm.stopPrank();

        assertEq(verifier.clientIdCount(), 1);
        assertFalse(verifier.isClientIdAllowed(keccak256(X_CLIENT_ID)));

        _verify(_payloadWithClientId(OTHER_CLIENT_ID));

        vm.expectRevert(XZkVerifier.ClientIdMismatch.selector);
        _verify(_payloadWithClientId(X_CLIENT_ID));
    }

    // ─── Permissive mode ─────────────────────────────────────────────

    function test_openClientIds_acceptsUnknownApp() public {
        vm.prank(OWNER);
        verifier.setOpenClientIds(true);

        _verify(_payloadWithClientId(OTHER_CLIENT_ID));
    }

    /// Permissive mode overrides even an empty allowlist — it is the flag, not
    /// emptiness, that grants access.
    function test_openClientIds_worksWithEmptyAllowlist() public {
        vm.startPrank(OWNER);
        verifier.removeClientId(X_CLIENT_ID);
        verifier.setOpenClientIds(true);
        vm.stopPrank();

        _verify(_payloadWithClientId(OTHER_CLIENT_ID));
    }

    function test_openClientIds_offAgain_deniesUnknownApp() public {
        vm.startPrank(OWNER);
        verifier.setOpenClientIds(true);
        verifier.setOpenClientIds(false);
        vm.stopPrank();

        vm.expectRevert(XZkVerifier.ClientIdMismatch.selector);
        _verify(_payloadWithClientId(OTHER_CLIENT_ID));
    }

    function test_setOpenClientIds_emitsEvent() public {
        vm.expectEmit(false, false, false, true, address(verifier));
        emit XZkVerifier.OpenClientIdsSet(true);
        vm.prank(OWNER);
        verifier.setOpenClientIds(true);
    }

    // ─── Admin guards ────────────────────────────────────────────────

    function test_addClientId_duplicate_reverts() public {
        vm.prank(OWNER);
        vm.expectRevert(XZkVerifier.ClientIdAlreadyAllowed.selector);
        verifier.addClientId(X_CLIENT_ID);
    }

    function test_removeClientId_unknown_reverts() public {
        vm.prank(OWNER);
        vm.expectRevert(XZkVerifier.ClientIdNotAllowed.selector);
        verifier.removeClientId(OTHER_CLIENT_ID);
    }

    function test_addClientId_emptyOrTooLong_reverts() public {
        vm.startPrank(OWNER);
        vm.expectRevert(XZkVerifier.BadClientIdLength.selector);
        verifier.addClientId(bytes(""));

        vm.expectRevert(XZkVerifier.BadClientIdLength.selector);
        verifier.addClientId(new bytes(65)); // MAX_CLIENT_ID_LEN is 64
        vm.stopPrank();
    }

    /// Verification scans once per entry, so the list is capped to bound gas.
    function test_addClientId_capEnforced() public {
        vm.startPrank(OWNER);
        // One seeded at init; fill to the cap of 16.
        for (uint256 i = 1; i < 16; i++) {
            verifier.addClientId(abi.encodePacked("app-", i));
        }
        assertEq(verifier.clientIdCount(), 16);

        vm.expectRevert(XZkVerifier.TooManyClientIds.selector);
        verifier.addClientId(bytes("one-too-many"));
        vm.stopPrank();
    }

    function test_adminFunctions_onlyOwner() public {
        address stranger = address(0xBAD);

        vm.startPrank(stranger);
        vm.expectRevert();
        verifier.addClientId(OTHER_CLIENT_ID);

        vm.expectRevert();
        verifier.removeClientId(X_CLIENT_ID);

        vm.expectRevert();
        verifier.setOpenClientIds(true);
        vm.stopPrank();
    }
}
