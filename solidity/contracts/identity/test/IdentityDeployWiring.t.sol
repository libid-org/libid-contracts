// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandleVectors} from "../HandleVectors.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {GooglePlatformVerifier} from "../../ceremony/GooglePlatformVerifier.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";

/// The deploy wires three platforms into one naming contract. A wrong rule set
/// there writes wrong keys for every name on that platform, and nothing later
/// would notice: the handle would simply resolve to nothing.
///
/// So the wiring is asserted rather than assumed — that the rules the deploy
/// installs are the ones `handles.json` states, and that every platform it
/// wires comes out resolvable.
contract IdentityDeployWiringTest is Test {
    IdentityNames internal names;
    CeremonyProofVerifier internal proofVerifier;
    address internal owner = makeAddr("owner");

    function setUp() public {
        IdentityNames impl = new IdentityNames();
        names =
            IdentityNames(address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityNames.initialize, (owner)))));
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        vm.prank(owner);
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
    }

    /// The rules come from the generated table, so a change to `handles.json`
    /// reaches the deploy without anybody editing it.
    function test_theGeneratedRulesAreTheOnesTheDeployInstalls() public {
        HandleNormalizer.Rules memory x = HandleVectors.rulesFor(HandleVectors.PLATFORM_X);
        assertEq(x.maxLength, uint16(HandleVectors.MAX_LENGTH_X), "X length");
        assertTrue(x.stripLeadingAt, "X strips a leading @");
        assertTrue(x.allowUnderscore, "X allows underscore");
        assertFalse(x.allowHyphen, "X allows no hyphen");
        assertFalse(x.isEmail, "X is not an email");

        HandleNormalizer.Rules memory gh = HandleVectors.rulesFor(HandleVectors.PLATFORM_GITHUB);
        assertEq(gh.maxLength, uint16(HandleVectors.MAX_LENGTH_GITHUB), "GitHub length");
        assertTrue(gh.allowHyphen, "GitHub allows hyphen");
        assertFalse(gh.allowUnderscore, "GitHub allows no underscore");

        HandleNormalizer.Rules memory g = HandleVectors.rulesFor(HandleVectors.PLATFORM_GOOGLE);
        assertEq(g.maxLength, uint16(HandleVectors.MAX_LENGTH_GOOGLE), "Google length");
        assertTrue(g.isEmail, "Google is an email");
        assertFalse(g.stripLeadingAt, "an email keeps its @");
    }

    /// An unknown platform reverts rather than returning a permissive default.
    /// A default would silently normalize with the wrong rules.
    function test_anUnknownPlatformHasNoRules() public {
        vm.expectRevert(bytes("unknown platform"));
        this.rulesForExternally(keccak256("nowhere"));
    }

    /// `rulesFor` is an internal library call, which `expectRevert` cannot see.
    /// This gives it a call boundary to watch.
    function rulesForExternally(bytes32 platformId) external pure returns (HandleNormalizer.Rules memory) {
        return HandleVectors.rulesFor(platformId);
    }

    /// Wiring all three the way the deploy does leaves each one resolvable.
    function test_theDeployWiringLeavesEveryPlatformUsable() public {
        vm.startPrank(owner);
        address x = _wireIdentityPlatform(HandleVectors.PLATFORM_X);
        address gh = _wireIdentityPlatform(HandleVectors.PLATFORM_GITHUB);
        address g = _wireIdentityPlatform(HandleVectors.PLATFORM_GOOGLE);
        vm.stopPrank();

        // The version a deployment registers its first verifier under.
        uint16 v = 1;
        assertEq(address(proofVerifier.verifierOf(HandleVectors.PLATFORM_X, v)), x);
        assertEq(address(proofVerifier.verifierOf(HandleVectors.PLATFORM_GITHUB, v)), gh);
        assertEq(address(proofVerifier.verifierOf(HandleVectors.PLATFORM_GOOGLE, v)), g);

        // Resolvable means the platform answers "nobody" rather than reverting
        // `UnknownPlatform`, which is what an unwired one does.
        assertEq(names.resolveHandle(HandleVectors.PLATFORM_X, "nobody"), address(0));
        assertEq(names.resolveHandle(HandleVectors.PLATFORM_GITHUB, "nobody"), address(0));
        assertEq(names.resolveHandle(HandleVectors.PLATFORM_GOOGLE, "nobody@example.com"), address(0));
    }

    /// The generated allowance is what a Platform Verifier must be initialized
    /// with, and nothing else derives it. Without a reader the table drifts
    /// silently: a verifier accepts any value up to its cap, so a
    /// mis-typed allowance is taken without complaint and mis-orders every
    /// cross-platform watermark from then on.
    function test_everyGeneratedAllowanceIsOneAVerifierWillAccept() public {
        // Read off a real verifier, not restated: a second copy of the cap
        // is the drift this test exists to catch.
        uint64 cap = new GooglePlatformVerifier().MAX_FUTURE_OBSERVATION_ALLOWANCE();
        assertLe(HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_X), cap, "X");
        assertLe(HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_GITHUB), cap, "GitHub");
        assertLe(HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_GOOGLE), cap, "Google");

        // And the ordering the numbers exist for: an OIDC claim carries the
        // token's `exp` and reads about an hour ahead, a notarized observation
        // is wall-clock and never is.
        assertGt(
            HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_GOOGLE),
            HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_X),
            "an OIDC claim is dated ahead, a notarized one is not"
        );
    }

    /// The deploy script's wiring, mirrored. Both sides call one helper so this
    /// test cannot drift from the script it exists to prove.
    function _wireIdentityPlatform(bytes32 platformId) internal returns (address verifier) {
        names.setPlatform(platformId, HandleVectors.rulesFor(platformId));
        verifier = address(new StubPlatformVerifier(platformId, 0));
        proofVerifier.setVerifier(platformId, 1, IPlatformVerifier(verifier));
    }
}
