// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";

/// @notice Pins the profile tags to fixed bytes.
/// @dev These strings are a cross-implementation agreement, not a reading of
///      the specification, which fixes only `libid.identity.pkce`. The notary
///      writes them and the verifier compares them; a silent disagreement
///      rejects every genuine attestation with no error that says why. The
///      expected values below were computed with `cast keccak`, independently
///      of this library.
contract CeremonyProfileTest is Test {
    function test_platformIdsArePinnedAndDistinct() public pure {
        assertEq(CeremonyProfile.PLATFORM_GOOGLE, 0x8f2f90d8304f6eb382d037c47a041d8c8b4d18bdd8b082fa32828e016a584ca7);
        assertEq(CeremonyProfile.PLATFORM_X, 0x7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83);
        assertEq(CeremonyProfile.PLATFORM_GITHUB, 0x07a17bd3c7c8d7b88e93a4d9007e3bc230b0a586a434de0bed6500e9f343deb7);
        assertTrue(CeremonyProfile.PLATFORM_GOOGLE != CeremonyProfile.PLATFORM_X);
        assertTrue(CeremonyProfile.PLATFORM_X != CeremonyProfile.PLATFORM_GITHUB);
        assertTrue(CeremonyProfile.PLATFORM_GOOGLE != CeremonyProfile.PLATFORM_GITHUB);
    }

    function test_authoritiesArePinned() public pure {
        assertEq(CeremonyProfile.AUTHORITY_X_API, 0x4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d);
        assertEq(CeremonyProfile.AUTHORITY_GITHUB, 0x06785da520052bf40d5bf506fb493c41162f55d4e17dffa8b21f02598e981533);
        assertEq(
            CeremonyProfile.AUTHORITY_GITHUB_API, 0xa5d9c1d593bc385a23a2d56116aab1951e3c66296476c7a7396a515105e8b2c1
        );
    }

    /// @dev GitHub's exchange is served by github.com and its identity read by
    ///      api.github.com, so one pinned authority per profile would be wrong.
    function test_githubNotarizesTwoDifferentAuthorities() public pure {
        assertTrue(CeremonyProfile.AUTHORITY_GITHUB != CeremonyProfile.AUTHORITY_GITHUB_API);
    }

    function test_attestationCountsFollowTheProfiles() public pure {
        // Google's path stops at the Platform Verifier and costs nothing.
        assertEq(CeremonyProfile.attestationCount(CeremonyProfile.PLATFORM_GOOGLE), 0);
        assertEq(CeremonyProfile.attestationCount(CeremonyProfile.PLATFORM_X), 2);
        assertEq(CeremonyProfile.attestationCount(CeremonyProfile.PLATFORM_GITHUB), 2);
    }

    function test_anUnknownPlatformHasNoCount() public {
        bytes32 unknown = keccak256("mastodon");
        vm.expectRevert(abi.encodeWithSelector(CeremonyProfile.UnknownPlatform.selector, unknown));
        this.count(unknown);
    }

    function count(bytes32 platformId) external pure returns (uint8) {
        return CeremonyProfile.attestationCount(platformId);
    }

    function test_launchParametersMatchThePublishedValues() public pure {
        assertEq(CeremonyProfile.LAUNCH_PROOF_LIFETIME_X, 3600);
        assertEq(CeremonyProfile.LAUNCH_PROOF_LIFETIME_GITHUB, 3600);
        assertEq(CeremonyProfile.LAUNCH_MAX_FUTURE_ATTESTATION_SKEW, 300);
        assertEq(CeremonyProfile.LAUNCH_VERSION, 1);
    }

    /// @dev The pinned fixture in CeremonyAttestation.t.sol opens with the
    ///      format tag, the X platform id and the identity session tag. If
    ///      these constants and that fixture ever drift apart, one of them is
    ///      wrong.
    function test_theAttestationFixtureUsesTheseConstants() public pure {
        assertEq(CeremonyProfile.PLATFORM_X, keccak256(bytes("x")));
    }
}
