// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandleVectors} from "../HandleVectors.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IdentityNodes} from "../IdentityNodes.sol";
import {IIdentityVerifier} from "../IIdentityVerifier.sol";
import {MockIdentityVerifier} from "./MockIdentityVerifier.sol";

/// @notice The identity contract, against a staged verifier.
///
/// @dev Every rule here belongs to the contract rather than to a provider, so a
///      mock verifier proves them for all three platforms at once.
contract IdentityNamesTest is Test {
    IdentityNames internal names;
    MockIdentityVerifier internal verifier;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    bytes32 internal constant GITHUB = HandleVectors.PLATFORM_GITHUB;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal owner = makeAddr("owner");
    address internal mallory = makeAddr("mallory");

    function setUp() public {
        IdentityNames impl = new IdentityNames();
        names =
            IdentityNames(address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityNames.initialize, (owner)))));
        verifier = new MockIdentityVerifier("mock");

        vm.startPrank(owner);
        _wire(X, address(verifier), NO_FUTURE_ALLOWANCE);
        _wire(GITHUB, address(verifier), NO_FUTURE_ALLOWANCE);
        vm.stopPrank();

        // Observations are provider timestamps, so the chain has to be past
        // them for a proof to read as already-made rather than future-dated.
        vm.warp(1_000_000);
    }

    /// The mock states wall-clock time, the way a notary does, so it never
    /// needs to claim an observation ahead of the chain.
    uint64 internal constant NO_FUTURE_ALLOWANCE = 0;

    /// The version every platform's first verifier lands on.
    uint32 internal constant V1 = 1;

    /// Configure a platform's keyspace and its first verifier, the way a
    /// deployment does. Caller supplies the prank.
    function _wire(bytes32 platformId, address verifierAddr, uint64 allowance) internal {
        names.setPlatform(platformId, HandleVectors.rulesFor(platformId));
        names.setVerifier(platformId, V1, IIdentityVerifier(verifierAddr), allowance);
    }

    /// Stage a claim and bind it as `who`.
    function _bind(address who, string memory userId, string memory handle, uint64 at) internal {
        verifier.stage(userId, handle, who, at);
        vm.prank(who);
        names.bind(X, hex"", false);
    }

    // ─── Binding ────────────────────────────────────────────────────

    function test_bindWritesBothMappings() public {
        _bind(alice, "123", "alice", 100);

        assertEq(names.resolveId(X, "123"), alice, "the id does not resolve");
        assertEq(names.resolveHandle(X, "alice"), alice, "the handle does not resolve");
    }

    /// The one authorization rule. A proof read from the mempool is useless to
    /// its reader, because spending it means being the address it names.
    function test_onlyTheProofsTargetMayBind() public {
        verifier.stage("123", "alice", alice, 100);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, alice, bob));
        names.bind(X, hex"", false);
    }

    /// A claim naming nobody is one anybody could redirect at themselves.
    function test_aClaimWithNoTargetIsRefused() public {
        verifier.stage("123", "alice", address(0), 100);

        vm.prank(alice);
        vm.expectRevert(IdentityNames.NoTarget.selector);
        names.bind(X, hex"", false);
    }

    function test_anUnconfiguredPlatformIsRefused() public {
        bytes32 unknown = keccak256("dyaka.identity.platform.nowhere");
        verifier.stage("123", "alice", alice, 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, unknown));
        names.bind(unknown, hex"", false);
    }

    /// The handle is normalized on the way in, so the key comes from the same
    /// transform every reader uses.
    function test_theHandleIsNormalizedOnTheWayIn() public {
        _bind(alice, "123", " @Alice_1 ", 100);

        assertEq(names.resolveHandle(X, "alice_1"), alice);
        assertEq(names.resolveHandle(X, "@ALICE_1"), alice, "a reader's spelling should not matter");
    }

    // ─── The watermark ──────────────────────────────────────────────

    /// A proof held back must not undo a newer one. This is the case the
    /// watermark exists for.
    function test_anOlderProofCannotTakeAHandleBack() public {
        _bind(alice, "123", "shared", 100);

        // Bob proves the same handle later, which is a legitimate takeover.
        _bind(bob, "456", "shared", 200);
        assertEq(names.resolveHandle(X, "shared"), bob);

        // Alice submits a proof she was holding from before bob's.
        verifier.stage("123", "shared", alice, 150);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(150), uint64(200)));
        names.bind(X, hex"", false);

        assertEq(names.resolveHandle(X, "shared"), bob, "the handle moved back");
    }

    /// Replaying the exact proof is refused by the same rule, because equal is
    /// not newer. That is why the contract needs no nullifier.
    function test_replayingAProofIsRefused() public {
        _bind(alice, "123", "alice", 100);

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(100), uint64(100)));
        names.bind(X, hex"", false);
    }

    /// The attack the future clamp exists for.
    ///
    /// A binding is superseded only by a strictly newer observation, so a proof
    /// dated far enough ahead would make every honest later proof read as
    /// stale. The owner's remedy for a name somebody else bound is to prove
    /// again — this is what stops that remedy being taken away for good.
    function test_aFutureDatedProofCannotLockAName() public {
        uint64 farAhead = uint64(block.timestamp) + 3650 days;
        verifier.stage("999", "alice", mallory, farAhead);

        vm.prank(mallory);
        vm.expectRevert(
            abi.encodeWithSelector(IdentityNames.ObservedInTheFuture.selector, farAhead, uint64(block.timestamp))
        );
        names.bind(X, hex"", false);

        // And the node is untouched, so the real owner still binds normally.
        _bind(alice, "123", "alice", uint64(block.timestamp));
        assertEq(names.resolveHandle(X, "alice"), alice);
    }

    /// The allowance is per platform because the platforms disagree on what
    /// "now" means: a notary states wall-clock time, while a Google claim
    /// carries the token's `exp`, about an hour ahead of issuance.
    function test_aPlatformMayAllowObservationsAhead() public {
        uint64 ahead = uint64(block.timestamp) + 30 minutes;

        // GITHUB is configured with no allowance, so the same claim is refused
        // there and accepted on a platform that permits it.
        verifier.stage("123", "alice", alice, ahead);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IdentityNames.ObservedInTheFuture.selector, ahead, uint64(block.timestamp))
        );
        names.bind(GITHUB, hex"", false);

        vm.prank(owner);
        names.setVerifier(GITHUB, V1, IIdentityVerifier(address(verifier)), 2 hours);

        verifier.stage("123", "alice", alice, ahead);
        vm.prank(alice);
        names.bind(GITHUB, hex"", false);
        assertEq(names.resolveHandle(GITHUB, "alice"), alice);
    }

    /// The boundary is inclusive: exactly at the limit is not "ahead".
    function test_anObservationExactlyAtTheLimitIsAccepted() public {
        vm.prank(owner);
        names.setVerifier(X, V1, IIdentityVerifier(address(verifier)), 1 hours);

        uint64 atLimit = uint64(block.timestamp) + 1 hours;
        verifier.stage("123", "alice", alice, atLimit);
        vm.prank(alice);
        names.bind(X, hex"", false);
        assertEq(names.resolveId(X, "123"), alice);
    }

    /// A rename keeps the id and takes a new handle. A rename is invisible to
    /// the chain until somebody proves the new state, and this second bind is
    /// that proof — so the handle the account left has to stop resolving, or a
    /// payment meant for whoever holds it now goes to the wallet that renamed
    /// away from it.
    function test_aRenameRetiresTheHandleTheAccountLeft() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        assertEq(names.resolveId(X, "123"), alice, "the id follows the account");
        assertEq(names.resolveHandle(X, "alice2"), alice);
        assertEq(names.resolveHandle(X, "alice"), address(0), "the handle it left no longer resolves");
    }

    /// Only the entry this account itself wrote. One wallet may hold two
    /// accounts on a platform, and the second may have taken the handle the
    /// first released — retiring that would delete a binding nobody renamed.
    function test_aRetirementSkipsAHandleAnotherAccountHasSinceTaken() public {
        _bind(alice, "123", "shared", 100);
        // A second account, same wallet, takes the handle the first held.
        _bind(alice, "456", "shared", 200);
        // Now the first account renames. Its own record still names "shared".
        _bind(alice, "123", "renamed", 300);

        assertEq(names.resolveHandle(X, "shared"), alice, "the second account keeps it");
        assertEq(names.resolveHandle(X, "renamed"), alice);
    }

    /// Retiring clears the owner and keeps the watermark. Deleting the whole
    /// record would return the node to `observedAt == 0` and let a proof older
    /// than the retired one take it.
    function test_aRetiredHandleStillOutranksAnOlderProof() public {
        _bind(alice, "123", "alice", 200);
        _bind(alice, "123", "alice2", 300);

        verifier.stage("456", "alice", bob, 100);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(100), uint64(200)));
        names.bind(X, hex"", false);
    }

    /// And a newer proof takes it as usual, so retiring frees the name rather
    /// than burning it.
    function test_aRetiredHandleIsFreeForANewerProof() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);
        _bind(bob, "456", "alice", 300);

        assertEq(names.resolveHandle(X, "alice"), bob);
    }

    /// A proof with no observation time cannot be ordered against any other, so
    /// it is refused rather than treated as the oldest.
    function test_aProofWithNoObservationTimeIsRefused() public {
        verifier.stage("123", "alice", alice, 0);
        vm.prank(alice);
        vm.expectRevert(IdentityNames.NoObservationTime.selector);
        names.bind(X, hex"", false);
    }

    /// Every shipped verifier refuses an empty id already. This is what keeps
    /// that true for a verifier written later: without it, every account such a
    /// verifier reported would land on the single node `idNode(platformId, "")`
    /// and take turns owning it.
    function test_aClaimWithNoAccountIdIsRefused() public {
        verifier.stage("", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(IdentityNames.NoUserId.selector);
        names.bind(X, hex"", false);
    }

    // ─── Platform configuration ─────────────────────────────────────

    /// A zero verifier reads as "remove this platform", and removal is not a
    /// power this contract offers: the names would stay in storage while
    /// `bind` and every resolver began reverting `UnknownPlatform`.
    function test_aPlatformCannotBeGivenAZeroVerifier() public {
        vm.prank(owner);
        vm.expectRevert(IdentityNames.NoVerifier.selector);
        names.setVerifier(X, V1, IIdentityVerifier(address(0)), NO_FUTURE_ALLOWANCE);
    }

    /// An allowance near the top of the range makes `_requireNotAhead` revert
    /// on its own arithmetic, bricking `bind` for the platform rather than
    /// widening its window.
    function test_anAbsurdFutureAllowanceIsRefused() public {
        // Read before pranking: `vm.prank` applies to the next call, and this
        // getter would be it.
        uint64 cap = names.MAX_FUTURE_OBSERVATION();

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.AllowanceTooLarge.selector, type(uint64).max, cap));
        names.setVerifier(X, V1, IIdentityVerifier(address(verifier)), type(uint64).max);
    }

    /// The real platforms sit far below the cap — Google needs about an hour —
    /// so the cap constrains nothing a deployment actually asks for.
    function test_aPlatformMayAllowUpToTheCap() public {
        uint64 cap = names.MAX_FUTURE_OBSERVATION();

        vm.prank(owner);
        names.setVerifier(X, V1, IIdentityVerifier(address(verifier)), cap);
    }

    // ─── The freshness signal ───────────────────────────────────────

    /// All three resolvers answer an unwired platform the same way. A zero
    /// address would tell a caller "nobody owns this name" when the truth is
    /// that the platform is not configured, and a zero cannot say which.
    function test_everyResolverRefusesAnUnknownPlatform() public {
        bytes32 unwired = keccak256("dyaka.identity.platform.nowhere");

        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, unwired));
        names.resolveId(unwired, "123");

        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, unwired));
        names.resolveHandle(unwired, "alice");

        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, unwired));
        names.resolvePair(unwired, "alice", "123");
    }

    function test_resolvePairAgreesWhileOneAccountHoldsBoth() public {
        _bind(alice, "123", "alice", 100);

        (address wallet, bool agrees) = names.resolvePair(X, "alice", "123");
        assertEq(wallet, alice);
        assertTrue(agrees, "one account holds both, so they must agree");
    }

    /// The case the two mappings exist for: a consumer holds a pair from two
    /// different moments, and the chain can say so.
    function test_resolvePairReportsAHandleThatChangedHands() public {
        _bind(alice, "123", "shared", 100);
        _bind(bob, "456", "shared", 200);

        (address wallet, bool agrees) = names.resolvePair(X, "shared", "123");
        assertEq(wallet, bob, "the handle routes to whoever proved it last");
        assertFalse(agrees, "the caller's id belongs to a different wallet now");
    }

    /// An id the chain has never seen leaves a caller exactly as uninformed as
    /// a stale one, so it does not agree either.
    function test_resolvePairDoesNotAgreeOnAnUnknownId() public {
        _bind(alice, "123", "alice", 100);

        (address wallet, bool agrees) = names.resolvePair(X, "alice", "999");
        assertEq(wallet, alice);
        assertFalse(agrees);
    }

    // ─── Reverse resolution ─────────────────────────────────────────

    function test_publishingIsOptional() public {
        _bind(alice, "123", "alice", 100);
        assertEq(bytes(names.reverseOf(alice, X)).length, 0, "nothing should be published by default");

        verifier.stage("123", "alice", alice, 200);
        vm.prank(alice);
        names.bind(X, hex"", true);
        assertEq(names.reverseOf(alice, X), "alice");
    }

    /// Publishing is the one thing here a user can undo, and it must not
    /// depend on being able to log in again: for Google the published handle is
    /// an email address, and withdrawing it should not require a fresh proof.
    function test_aPublishedNameCanBeWithdrawn() public {
        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        names.bind(X, hex"", true);
        assertEq(names.reverseOf(alice, X), "alice");

        vm.prank(alice);
        names.unpublish(X);
        assertEq(bytes(names.reverseOf(alice, X)).length, 0);
        assertEq(bytes(names.primaryOf(alice, X)).length, 0);
    }

    /// The binding survives. This withdraws a displayed string, not the proof
    /// of who owns the account.
    function test_withdrawingAPublishedNameKeepsTheBinding() public {
        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        names.bind(X, hex"", true);

        vm.prank(alice);
        names.unpublish(X);

        assertEq(names.resolveId(X, "123"), alice);
        assertEq(names.resolveHandle(X, "alice"), alice);
    }

    /// Binding again with `publishName: false` must NOT withdraw an earlier
    /// publish — a caller re-proving after a rename should not silently drop a
    /// name because a flag defaulted, and withdrawing has its own door. It must
    /// not leave the OLD name on display either: the wallet just proved it
    /// holds a different one.
    function test_bindingAgainRefreshesAPublishedNameRatherThanWithdrawingIt() public {
        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        names.bind(X, hex"", true);

        verifier.stage("123", "alice2", alice, 200);
        vm.prank(alice);
        names.bind(X, hex"", false);

        assertEq(names.reverseOf(alice, X), "alice2", "the display follows the name it holds");
        assertEq(names.primaryOf(alice, X), "alice2", "and it still resolves back");
    }

    /// The complement: a wallet that never published does not start now.
    function test_bindingWithoutPublishingStillPublishesNothing() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        assertEq(names.reverseOf(alice, X), "", "nothing was ever on display");
    }

    /// An indexer mirrors `reverseOf` from the log alone, so the log has to say
    /// whether the handle is on display. Only `unpublish` is observable
    /// otherwise, and a publish would have to be guessed.
    function test_theLogSaysWhetherTheNameIsPublished() public {
        verifier.stage("123", "alice", alice, 100);
        vm.recordLogs();
        vm.prank(alice);
        names.bind(X, hex"", true);
        assertTrue(_lastBindPublished(), "published");

        verifier.stage("456", "bob", bob, 100);
        vm.recordLogs();
        vm.prank(bob);
        names.bind(X, hex"", false);
        assertFalse(_lastBindPublished(), "not published");
    }

    /// The refresh is observable too, or an indexer would still hold the name
    /// the wallet renamed away from.
    function test_theLogSaysPublishedWhenARefreshKeepsTheNameOnDisplay() public {
        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        names.bind(X, hex"", true);

        verifier.stage("123", "alice2", alice, 200);
        vm.recordLogs();
        vm.prank(alice);
        names.bind(X, hex"", false);

        assertTrue(_lastBindPublished(), "the flag was false, the name is still on display");
    }

    /// The `published` flag and the proof version out of the last
    /// `IdentityBound` in the recorded logs.
    function _lastBind() internal returns (bool published, uint32 version) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("IdentityBound(address,bytes32,bytes32,bytes32,string,string,uint64,bool,uint32)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] != topic) continue;
            (,,,, published, version) = abi.decode(logs[i - 1].data, (bytes32, string, string, uint64, bool, uint32));
            return (published, version);
        }
        revert("no IdentityBound in the logs");
    }

    function _lastBindPublished() internal returns (bool published) {
        (published,) = _lastBind();
    }

    /// One wallet's withdrawal is its own. There is no path to another's.
    function test_withdrawingTouchesOnlyTheCallersRecord() public {
        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        names.bind(X, hex"", true);

        vm.prank(mallory);
        names.unpublish(X);

        assertEq(names.reverseOf(alice, X), "alice");
    }

    /// The forward check ENS requires of its integrators, done here so an
    /// integrator cannot skip it.
    function test_primaryOfGoesEmptyOnceTheHandleMovesOn() public {
        verifier.stage("123", "shared", alice, 100);
        vm.prank(alice);
        names.bind(X, hex"", true);
        assertEq(names.primaryOf(alice, X), "shared", "it resolves back, so it stands");

        // Bob proves the same handle. Alice's published name is now somebody
        // else's, though nothing rewrote her record.
        _bind(bob, "456", "shared", 200);

        assertEq(names.reverseOf(alice, X), "shared", "the raw record is untouched");
        assertEq(names.primaryOf(alice, X), "", "but it no longer resolves back");
    }

    // ─── Reading is total in the handle ─────────────────────────────

    /// A contract resolving whatever a user typed must not have its whole
    /// transaction reverted by a stray space, with a library error it cannot
    /// tell apart from `UnknownPlatform`. Text nobody could hold answers the
    /// zero address, which is the same answer as text nobody does hold.
    function test_resolvingTextNoPlatformCouldHoldAnswersNobody() public view {
        assertEq(names.resolveHandle(X, "ali ce"), address(0), "a stray space");
        assertEq(names.resolveHandle(X, unicode"aliçe"), address(0), "a byte above 0x7f");
        assertEq(names.resolveHandle(X, ""), address(0), "nothing at all");
        assertEq(names.resolveHandle(X, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), address(0), "too long");
        assertEq(names.resolveHandle(GITHUB, "-octocat"), address(0), "an arrangement the platform refuses");
    }

    /// `resolvePair` matters more: its documented job is to let a caller decide
    /// what to tell a user, not to refuse.
    function test_resolvePairAnswersRatherThanRevertingOnAMalformedHandle() public view {
        (address wallet, bool idAgrees) = names.resolvePair(X, "ali ce", "123");
        assertEq(wallet, address(0));
        assertFalse(idAgrees);
    }

    /// An unwired platform still reverts. Zero would answer "nobody holds this"
    /// to a question that was never asked, and the caller cannot tell the two
    /// apart from an address.
    function test_anUnwiredPlatformStillReverts() public {
        bytes32 unknown = keccak256("nowhere");
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, unknown));
        names.resolveHandle(unknown, "alice");
    }

    /// `bind` keeps reverting. A handle that arrives inside a proof and does
    /// not normalize is a broken proof, and failing loudly is right.
    function test_bindStillRefusesAHandleThatDoesNotNormalize() public {
        verifier.stage("123", "ali ce", alice, 100);
        vm.prank(alice);
        vm.expectRevert(HandleNormalizer.BadCharacter.selector);
        names.bind(X, hex"", false);
    }

    /// After the owner narrows a platform's rules, an already-written handle
    /// keys to a node the forward resolver can no longer name. `primaryOf` must
    /// go with it: handing out a name `resolveHandle` refuses would contradict
    /// both its own promise and the statement that re-keyed entries no longer
    /// answer the public resolvers.
    function test_primaryOfGoesEmptyWhenTheRulesNoLongerAllowTheName() public {
        verifier.stage("123", "octo-cat", alice, 100);
        vm.prank(alice);
        names.bind(GITHUB, hex"", true);
        assertEq(names.primaryOf(alice, GITHUB), "octo-cat");

        HandleNormalizer.Rules memory narrowed = HandleVectors.rulesFor(GITHUB);
        narrowed.allowHyphen = false;
        vm.prank(owner);
        names.setPlatform(GITHUB, narrowed);

        assertEq(names.resolveHandle(GITHUB, "octo-cat"), address(0), "the forward resolver cannot name it");
        assertEq(names.primaryOf(alice, GITHUB), "", "so neither does the reverse one");
        assertEq(names.reverseOf(alice, GITHUB), "octo-cat", "the raw record is untouched");
    }

    // ─── Node separation ────────────────────────────────────────────

    /// A numeric handle and an account id of the same digits must not collide.
    /// Numeric handles are legal on X and old account ids are short, so this is
    /// reachable rather than theoretical.
    function test_aNumericHandleDoesNotCollideWithAnAccountId() public {
        assertTrue(
            IdentityNodes.idNode(X, "12345") != IdentityNodes.handleNode(X, "12345"),
            "an id node and a handle node collided"
        );

        _bind(alice, "12345", "bob", 100);
        _bind(bob, "999", "12345", 100);

        assertEq(names.resolveId(X, "12345"), alice, "the id belongs to alice");
        assertEq(names.resolveHandle(X, "12345"), bob, "the handle belongs to bob");
    }

    /// The same text on two platforms is two identities.
    function test_platformsDoNotShareAKeyspace() public {
        _bind(alice, "123", "alice", 100);

        verifier.stage("123", "alice", bob, 100);
        vm.prank(bob);
        names.bind(GITHUB, hex"", false);

        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(names.resolveHandle(GITHUB, "alice"), bob);
    }

    // ─── Proof versions ─────────────────────────────────────────────
    //
    // A platform's proof can change shape without the account behind it
    // changing — X gaining OIDC, say. Both formats have to be accepted while
    // users migrate, so the verifier is keyed by version and the keyspace is
    // not.

    /// The first verifier a platform gets becomes its default, because
    /// requiring a second call would only invite a half-configured platform.
    function test_theFirstVersionBecomesTheLatest() public view {
        assertEq(names.latestVersionOf(X), V1);
        assertEq(address(names.verifierOf(X, V1)), address(verifier));
    }

    /// Registering a new version must NOT redirect anybody. A format is
    /// deployed, exercised against the real chain, and only then made default.
    function test_registeringAVersionDoesNotMoveTheDefault() public {
        MockIdentityVerifier v2 = new MockIdentityVerifier("v2");
        vm.prank(owner);
        names.setVerifier(X, 2, IIdentityVerifier(address(v2)), NO_FUTURE_ALLOWANCE);

        assertEq(names.latestVersionOf(X), V1, "the default moved on its own");
        assertEq(address(names.verifierOf(X, 2)), address(v2), "but the version is installed");
    }

    /// Two formats accepted at once — the whole point.
    function test_twoVersionsBindSideBySide() public {
        MockIdentityVerifier v2 = _addVersion(2, NO_FUTURE_ALLOWANCE);

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        names.bindAtVersion(X, V1, hex"", false);

        v2.stage("456", "bob", bob, 100);
        vm.prank(bob);
        names.bindAtVersion(X, 2, hex"", false);

        assertEq(names.resolveHandle(X, "alice"), alice, "the old format still binds");
        assertEq(names.resolveHandle(X, "bob"), bob, "and the new one does too");
    }

    /// Moving the default is the migration switch, and it moves only what a
    /// caller that names no version gets.
    function test_movingTheDefaultChangesWhatPlainBindUses() public {
        MockIdentityVerifier v2 = _addVersion(2, NO_FUTURE_ALLOWANCE);
        vm.prank(owner);
        names.setLatestVersion(X, 2);

        // Only v2 has a claim staged, so a plain bind reaching v1 would find
        // an empty one and revert.
        v2.stage("456", "bob", bob, 100);
        vm.prank(bob);
        names.bind(X, hex"", false);

        assertEq(names.resolveHandle(X, "bob"), bob);
        assertEq(names.latestVersionOf(X), 2);
    }

    /// A client mid-migration names the version it built its proof for, and
    /// keeps working the day the default moves.
    function test_anOlderVersionStillBindsAfterTheDefaultMoves() public {
        _addVersion(2, NO_FUTURE_ALLOWANCE);
        vm.prank(owner);
        names.setLatestVersion(X, 2);

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        names.bindAtVersion(X, V1, hex"", false);

        assertEq(names.resolveHandle(X, "alice"), alice);
    }

    function test_aVersionWithNoVerifierIsRefused() public {
        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownVersion.selector, X, uint32(7)));
        names.bindAtVersion(X, 7, hex"", false);
    }

    /// The end of a migration: the format stops being accepted.
    function test_retiringAVersionStopsNewBindings() public {
        _addVersion(2, NO_FUTURE_ALLOWANCE);
        vm.startPrank(owner);
        names.setLatestVersion(X, 2);
        names.retireVerifier(X, V1);
        vm.stopPrank();

        verifier.stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownVersion.selector, X, V1));
        names.bindAtVersion(X, V1, hex"", false);
    }

    /// A name belongs to the account that proved it, not to the format the
    /// proof was written in. Retiring a version must not unbind anybody.
    function test_retiringAVersionLeavesItsNamesResolving() public {
        _bind(alice, "123", "alice", 100);
        _addVersion(2, NO_FUTURE_ALLOWANCE);

        vm.startPrank(owner);
        names.setLatestVersion(X, 2);
        names.retireVerifier(X, V1);
        vm.stopPrank();

        assertEq(names.resolveHandle(X, "alice"), alice, "the name went with the format");
        assertEq(names.resolveId(X, "123"), alice);
    }

    /// Retiring the default would leave the platform answering `bind` while
    /// accepting nothing. Move the default first.
    function test_theDefaultVersionCannotBeRetired() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.VersionInUseAsLatest.selector, X, V1));
        names.retireVerifier(X, V1);
    }

    /// Whether a version is still in use has to be answerable BEFORE retiring
    /// it, or the owner is guessing. The binding carries the version, and it
    /// costs no extra storage: 20 + 8 + 4 bytes is one word.
    function test_theBindingRecordsWhichVersionProvedIt() public {
        MockIdentityVerifier v2 = _addVersion(2, NO_FUTURE_ALLOWANCE);

        v2.stage("456", "bob", bob, 100);
        vm.recordLogs();
        vm.prank(bob);
        names.bindAtVersion(X, 2, hex"", false);

        (,, uint32 idVersion) = names.byId(IdentityNodes.idNode(X, "456"));
        (,, uint32 handleVersion) = names.byHandle(IdentityNodes.handleNode(X, "bob"));
        assertEq(idVersion, 2, "the id node");
        assertEq(handleVersion, 2, "the handle node");

        (, uint32 logged) = _lastBind();
        assertEq(logged, 2, "and the log an indexer reads");
    }

    /// The allowance travels with the version, not the platform: a notary
    /// states wall-clock time and is never ahead, while an OIDC claim carries
    /// the token's `exp` and reads about an hour ahead. One number for both
    /// would either reject every OIDC bind or hand the notary a window it
    /// never needed.
    function test_theFutureAllowanceIsPerVersion() public {
        MockIdentityVerifier v2 = _addVersion(2, 2 hours);
        uint64 ahead = uint64(block.timestamp) + 30 minutes;

        // v1 carries no allowance, so the same observation is refused there.
        verifier.stage("123", "alice", alice, ahead);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IdentityNames.ObservedInTheFuture.selector, ahead, uint64(block.timestamp))
        );
        names.bindAtVersion(X, V1, hex"", false);

        v2.stage("123", "alice", alice, ahead);
        vm.prank(alice);
        names.bindAtVersion(X, 2, hex"", false);
        assertEq(names.resolveHandle(X, "alice"), alice);
    }

    // ─── Version configuration ──────────────────────────────────────

    /// Zero is the "no verifier" sentinel — an unconfigured platform reads
    /// `latestVersion == 0` — so it cannot also name a real version.
    function test_versionZeroCannotNameAVerifier() public {
        vm.prank(owner);
        vm.expectRevert(IdentityNames.ZeroVersion.selector);
        names.setVerifier(X, 0, IIdentityVerifier(address(verifier)), NO_FUTURE_ALLOWANCE);
    }

    /// A verifier needs a keyspace to write into. Without this the platform
    /// would accept proofs while every resolver reverted `UnknownPlatform`.
    function test_aVerifierNeedsItsPlatformConfiguredFirst() public {
        bytes32 nowhere = keccak256("dyaka.identity.platform.nowhere");
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, nowhere));
        names.setVerifier(nowhere, V1, IIdentityVerifier(address(verifier)), NO_FUTURE_ALLOWANCE);
    }

    function test_theDefaultCannotPointAtAVersionThatDoesNotExist() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownVersion.selector, X, uint32(9)));
        names.setLatestVersion(X, 9);
    }

    function test_retiringAVersionThatWasNeverThereIsRefused() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownVersion.selector, X, uint32(9)));
        names.retireVerifier(X, 9);
    }

    function test_onlyTheOwnerMovesTheDefaultOrRetiresAVersion() public {
        _addVersion(2, NO_FUTURE_ALLOWANCE);

        vm.prank(alice);
        vm.expectRevert();
        names.setLatestVersion(X, 2);

        vm.prank(alice);
        vm.expectRevert();
        names.retireVerifier(X, 2);
    }

    /// Install a fresh verifier for `version` on X and return it.
    function _addVersion(uint32 version, uint64 allowance) internal returns (MockIdentityVerifier v) {
        v = new MockIdentityVerifier("extra");
        vm.prank(owner);
        names.setVerifier(X, version, IIdentityVerifier(address(v)), allowance);
    }

    // ─── Ownership ──────────────────────────────────────────────────

    /// The owner has no privileged path to a binding. It obeys the same target
    /// rule as anybody else, so holding the owner key does not let it spend a
    /// proof that names a different address.
    function test_theOwnerHasNoPrivilegedPathToABinding() public {
        _bind(alice, "123", "alice", 100);

        verifier.stage("123", "alice", alice, 200);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, alice, owner));
        names.bind(X, hex"", false);

        assertEq(names.resolveId(X, "123"), alice, "the binding moved");
    }

    /// Configuring a platform is the whole of the owner's power, and it reaches
    /// no existing binding. Replacing a verifier must not disturb a name that
    /// the previous verifier's proof established.
    function test_reconfiguringAPlatformLeavesBindingsAlone() public {
        _bind(alice, "123", "alice", 100);

        MockIdentityVerifier replacement = new MockIdentityVerifier("replacement");
        vm.prank(owner);
        names.setVerifier(X, V1, IIdentityVerifier(address(replacement)), NO_FUTURE_ALLOWANCE);

        assertEq(names.resolveId(X, "123"), alice);
        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(address(names.verifierOf(X, V1)), address(replacement));
    }

    function test_onlyTheOwnerConfiguresAPlatform() public {
        vm.prank(alice);
        vm.expectRevert();
        names.setPlatform(X, HandleVectors.rulesFor(X));
    }

    function test_onlyTheOwnerConfiguresAVerifier() public {
        vm.prank(alice);
        vm.expectRevert();
        names.setVerifier(X, V1, IIdentityVerifier(address(verifier)), NO_FUTURE_ALLOWANCE);
    }
}
