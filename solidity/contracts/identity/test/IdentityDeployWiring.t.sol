// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandleVectors} from "../HandleVectors.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IIdentityVerifier} from "../IIdentityVerifier.sol";

/// The deploy wires three platforms into one naming contract. A wrong rule set
/// there writes wrong keys for every name on that platform, and nothing later
/// would notice: the handle would simply resolve to nothing.
///
/// So the wiring is asserted rather than assumed — that the rules the deploy
/// installs are the ones `handles.json` states, and that the future allowance
/// each platform gets matches what its proofs actually report.
contract IdentityDeployWiringTest is Test {
    IdentityNames internal names;
    address internal owner = makeAddr("owner");

    function setUp() public {
        IdentityNames impl = new IdentityNames();
        names =
            IdentityNames(address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityNames.initialize, (owner)))));
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
        this.rulesForExternally(keccak256("dyaka.identity.platform.nowhere"));
    }

    /// `rulesFor` is an internal library call, which `expectRevert` cannot see.
    /// This gives it a call boundary to watch.
    function rulesForExternally(bytes32 platformId) external pure returns (HandleNormalizer.Rules memory) {
        return HandleVectors.rulesFor(platformId);
    }

    /// Wiring all three the way the deploy does leaves each one resolvable, and
    /// the OIDC allowance wider than the notary one — which is the whole reason
    /// the allowance is per platform.
    function test_theDeployWiringLeavesEveryPlatformUsable() public {
        address xVerifier = makeAddr("x verifier");
        address ghVerifier = makeAddr("github verifier");
        address gVerifier = makeAddr("google verifier");

        vm.startPrank(owner);
        names.setPlatform(
            HandleVectors.PLATFORM_X,
            IIdentityVerifier(xVerifier),
            HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_X),
            HandleVectors.rulesFor(HandleVectors.PLATFORM_X)
        );
        names.setPlatform(
            HandleVectors.PLATFORM_GITHUB,
            IIdentityVerifier(ghVerifier),
            HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_GITHUB),
            HandleVectors.rulesFor(HandleVectors.PLATFORM_GITHUB)
        );
        names.setPlatform(
            HandleVectors.PLATFORM_GOOGLE,
            IIdentityVerifier(gVerifier),
            HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_GOOGLE),
            HandleVectors.rulesFor(HandleVectors.PLATFORM_GOOGLE)
        );
        vm.stopPrank();

        assertEq(address(names.verifierOf(HandleVectors.PLATFORM_X)), xVerifier);
        assertEq(address(names.verifierOf(HandleVectors.PLATFORM_GITHUB)), ghVerifier);
        assertEq(address(names.verifierOf(HandleVectors.PLATFORM_GOOGLE)), gVerifier);

        assertGt(
            HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_GOOGLE),
            HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_X),
            "an OIDC claim is dated ahead, a notarized one is not"
        );
    }

    /// `setPlatform` refuses an allowance past its cap, so a platform raised
    /// beyond it would fail the deploy rather than the review. This is what
    /// says so before the deploy runs.
    function test_everyPlatformAllowanceFitsUnderTheCap() public view {
        uint64 cap = names.MAX_FUTURE_OBSERVATION();
        assertLe(HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_X), cap, "X");
        assertLe(HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_GITHUB), cap, "GitHub");
        assertLe(HandleVectors.futureAllowanceFor(HandleVectors.PLATFORM_GOOGLE), cap, "Google");
    }

    /// `futureAllowanceFor` refuses an unknown platform rather than handing the
    /// deploy a zero, which would read as "this platform is never ahead" and
    /// silently reject every Google binding.
    function test_anUnknownPlatformHasNoAllowance() public {
        vm.expectRevert(bytes("unknown platform"));
        this.allowanceForExternally(keccak256("dyaka.identity.platform.nowhere"));
    }

    /// An external hop, because `vm.expectRevert` cannot see into an internal
    /// library call.
    function allowanceForExternally(bytes32 platformId) external pure returns (uint64) {
        return HandleVectors.futureAllowanceFor(platformId);
    }
}
