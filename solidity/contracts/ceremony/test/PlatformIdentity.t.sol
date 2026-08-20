// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyProfile} from "../CeremonyProfile.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {IdentityNodes} from "../../identity/IdentityNodes.sol";

/// @notice One keyspace per platform, and libID namespaces only its own things.
///
/// @dev These two tables used to disagree. The naming system keyed a platform
///      by `keccak256("dyaka.identity.platform.x")` and the ceremony profile by
///      `keccak256("x")`, so a name bound through one path was invisible to the
///      other -- two keyspaces for one platform, with nothing to make the
///      divergence loud. This file is what makes it loud.
contract PlatformIdentityTest is Test {
    /// @dev REQ-COMMON-55 fixes `platformId` as the keccak256 of the UTF-8
    ///      bytes of the identity-platform NAME. The notary derives the same
    ///      value when it signs, so a namespace of our own here would make
    ///      every genuine attestation name a platform no verifier recognizes.
    function test_theTwoTablesAgree() public pure {
        assertEq(HandleVectors.PLATFORM_X, CeremonyProfile.PLATFORM_X, "x");
        assertEq(HandleVectors.PLATFORM_GITHUB, CeremonyProfile.PLATFORM_GITHUB, "github");
        assertEq(HandleVectors.PLATFORM_GOOGLE, CeremonyProfile.PLATFORM_GOOGLE, "google");
    }

    function test_aPlatformIdIsTheBareName() public pure {
        assertEq(CeremonyProfile.PLATFORM_X, keccak256(bytes("x")));
        assertEq(CeremonyProfile.PLATFORM_GITHUB, keccak256(bytes("github")));
        assertEq(CeremonyProfile.PLATFORM_GOOGLE, keccak256(bytes("google")));
    }

    /// @dev A platform's name is not libID's to namespace; libID's own
    ///      constructs are. The node tags, the attestation format tag and the
    ///      session tags all carry the prefix, and none of them says `dyaka`.
    function test_libidNamespacesOnlyItsOwnConstructs() public pure {
        assertEq(IdentityNodes.ID_NODE_V1, keccak256(bytes("libid.identity.id-node.v1")));
        assertEq(IdentityNodes.HANDLE_NODE_V1, keccak256(bytes("libid.identity.handle-node.v1")));
        assertEq(CeremonyProfile.FORMAT_TAG, keccak256(bytes("libid.attestation.v1")));
        assertEq(CeremonyProfile.TOKEN_SESSION_TAG, keccak256(bytes("libid.ceremony.session.token.v1")));
    }

    /// @dev The node tags are what every stored key hangs off, so changing one
    ///      rekeys the whole system. Pinned so it cannot happen quietly.
    function test_theNodeTagsArePinned() public pure {
        assertEq(
            IdentityNodes.idNode(CeremonyProfile.PLATFORM_X, "2244994945"),
            keccak256(
                abi.encode(
                    keccak256(bytes("libid.identity.id-node.v1")), keccak256(bytes("x")), keccak256(bytes("2244994945"))
                )
            )
        );
    }
}
