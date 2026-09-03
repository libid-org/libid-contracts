// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandleVectors} from "../HandleVectors.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IdentityNodes} from "../IdentityNodes.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice The identity contract, against a stubbed Platform Verifier.
///
/// @dev Every rule here belongs to the Consumer rather than to a platform, so
///      one stub proves them for both platforms at once. What a real Platform
///      Verifier checks — the attestations, the proof, the freshness window —
///      has its own suite.
contract IdentityNamesTest is Test {
    IdentityNames internal names;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;
    StubPlatformVerifier internal githubVerifier;

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
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        xVerifier = new StubPlatformVerifier(X, 0);
        githubVerifier = new StubPlatformVerifier(GITHUB, 0);

        vm.startPrank(owner);
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
        _wire(X, address(xVerifier));
        _wire(GITHUB, address(githubVerifier));
        vm.stopPrank();

        // Observations are provider timestamps, so the chain has to be past
        // them for a proof to read as already-made rather than future-dated.
        vm.warp(1_000_000);
    }

    /// The version every platform's first verifier lands on.
    uint16 internal constant V1 = 1;

    /// Configure a platform's keyspace and its first verifier, the way a
    /// deployment does. Caller supplies the prank.
    function _wire(bytes32 platformId, address verifierAddr) internal {
        names.setPlatform(platformId, HandleVectors.rulesFor(platformId));
        proofVerifier.setVerifier(platformId, V1, IPlatformVerifier(verifierAddr));
    }

    /// Who the next submission's Authorized Transaction Data names.
    address private stagedTarget;

    /// A digest is spendable once, so every claim needs a nonce of its own.
    uint256 private nonce;

    /// Stage what the Platform Verifier reports, and who the submission names.
    ///
    /// @dev The stubs are written HERE rather than in `_claim`, because a test
    ///      pranks between the two and `vm.prank` is spent on the next external
    ///      call. Writing them later would spend it on the stub and send the
    ///      claim from the test contract.
    function _stage(string memory userId, string memory handle, address target, uint64 at) internal {
        stagedTarget = target;
        xVerifier.set(userId, handle);
        xVerifier.setObservedAt(at);
        githubVerifier.set(userId, handle);
        githubVerifier.setObservedAt(at);
    }

    /// The stub's payload for the staged target, under the ceremony version
    /// the stub will echo back.
    function _payload(uint16 ceremonyVersion) internal returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: ceremonyVersion,
                // A literal, not `names.CLAIM_IDENTITY_DOMAIN()`: reading it
                // is an external call, and it would spend the caller's prank.
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                transactionData: abi.encode(stagedTarget)
            })
        );
    }

    /// Submit the staged claim. The caller supplies the prank, the way a
    /// wallet supplies `msg.sender`.
    function _claim(bytes32 platformId, bool publishName) internal {
        bytes memory payload = _payload(V1);
        names.claim(platformId, V1, payload, publishName);
    }

    /// Stage a claim and bind it as `who`.
    function _bind(address who, string memory userId, string memory handle, uint64 at) internal {
        _stage(userId, handle, who, at);
        vm.prank(who);
        _claim(X, false);
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
        _stage("123", "alice", alice, 100);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, alice, bob));
        _claim(X, false);
    }

    /// Authorized Transaction Data naming nobody is data anybody could redirect
    /// at themselves. It is refused the same way any other address that is not
    /// the caller is.
    function test_aClaimWithNoTargetIsRefused() public {
        _stage("123", "alice", address(0), 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, address(0), alice));
        _claim(X, false);
    }

    function test_anUnconfiguredPlatformIsRefused() public {
        bytes32 unknown = keccak256("nowhere");
        _stage("123", "alice", alice, 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, unknown));
        _claim(unknown, false);
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
        _stage("123", "shared", alice, 150);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(150), uint64(200)));
        _claim(X, false);

        assertEq(names.resolveHandle(X, "shared"), bob, "the handle moved back");
    }

    /// Replaying the exact proof is refused by the same rule, because equal is
    /// not newer. That is why the contract needs no nullifier.
    function test_replayingAProofIsRefused() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(100), uint64(100)));
        _claim(X, false);
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

        _stage("456", "alice", bob, 100);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(100), uint64(200)));
        _claim(X, false);
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
        _stage("123", "alice", alice, 0);
        vm.prank(alice);
        vm.expectRevert(IdentityNames.NoObservationTime.selector);
        _claim(X, false);
    }

    /// Every shipped verifier refuses an empty id already. This is what keeps
    /// that true for a verifier written later: without it, every account such a
    /// verifier reported would land on the single node `idNode(platformId, "")`
    /// and take turns owning it.
    function test_aClaimWithNoAccountIdIsRefused() public {
        _stage("", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(IdentityNames.NoUserId.selector);
        _claim(X, false);
    }

    // ─── Platform configuration ─────────────────────────────────────

    // ─── The freshness signal ───────────────────────────────────────

    /// All three resolvers answer an unwired platform the same way. A zero
    /// address would tell a caller "nobody owns this name" when the truth is
    /// that the platform is not configured, and a zero cannot say which.
    function test_everyResolverRefusesAnUnknownPlatform() public {
        bytes32 unwired = keccak256("nowhere");

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

        _stage("123", "alice", alice, 200);
        vm.prank(alice);
        _claim(X, true);
        assertEq(names.reverseOf(alice, X), "alice");
    }

    /// Publishing is the one thing here a user can undo, and it must not
    /// depend on being able to log in again: for Google the published handle is
    /// an email address, and withdrawing it should not require a fresh proof.
    function test_aPublishedNameCanBeWithdrawn() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);
        assertEq(names.reverseOf(alice, X), "alice");

        vm.prank(alice);
        names.unpublish(X);
        assertEq(bytes(names.reverseOf(alice, X)).length, 0);
        assertEq(bytes(names.primaryOf(alice, X)).length, 0);
    }

    /// The binding survives. This withdraws a displayed string, not the proof
    /// of who owns the account.
    function test_withdrawingAPublishedNameKeepsTheBinding() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);

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
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);

        _stage("123", "alice2", alice, 200);
        vm.prank(alice);
        _claim(X, false);

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
        _stage("123", "alice", alice, 100);
        vm.recordLogs();
        vm.prank(alice);
        _claim(X, true);
        assertTrue(_lastBindPublished(), "published");

        _stage("456", "bob", bob, 100);
        vm.recordLogs();
        vm.prank(bob);
        _claim(X, false);
        assertFalse(_lastBindPublished(), "not published");
    }

    /// The refresh is observable too, or an indexer would still hold the name
    /// the wallet renamed away from.
    function test_theLogSaysPublishedWhenARefreshKeepsTheNameOnDisplay() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);

        _stage("123", "alice2", alice, 200);
        vm.recordLogs();
        vm.prank(alice);
        _claim(X, false);

        assertTrue(_lastBindPublished(), "the flag was false, the name is still on display");
    }

    /// The `published` flag and the ceremony version out of the last
    /// `IdentityBound` in the recorded logs.
    function _lastBind() internal returns (bool published, uint16 ceremonyVersion) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("IdentityBound(address,bytes32,bytes32,bytes32,string,string,uint64,bool,uint16)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] != topic) continue;
            (,,,, published, ceremonyVersion) =
                abi.decode(logs[i - 1].data, (bytes32, string, string, uint64, bool, uint16));
            return (published, ceremonyVersion);
        }
        revert("no IdentityBound in the logs");
    }

    function _lastBindPublished() internal returns (bool published) {
        (published,) = _lastBind();
    }

    /// One wallet's withdrawal is its own. There is no path to another's.
    function test_withdrawingTouchesOnlyTheCallersRecord() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);

        vm.prank(mallory);
        names.unpublish(X);

        assertEq(names.reverseOf(alice, X), "alice");
    }

    /// The forward check ENS requires of its integrators, done here so an
    /// integrator cannot skip it.
    function test_primaryOfGoesEmptyOnceTheHandleMovesOn() public {
        _stage("123", "shared", alice, 100);
        vm.prank(alice);
        _claim(X, true);
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
        _stage("123", "ali ce", alice, 100);
        vm.prank(alice);
        vm.expectRevert(HandleNormalizer.BadCharacter.selector);
        _claim(X, false);
    }

    /// After the owner narrows a platform's rules, an already-written handle
    /// keys to a node the forward resolver can no longer name. `primaryOf` must
    /// go with it: handing out a name `resolveHandle` refuses would contradict
    /// both its own promise and the statement that re-keyed entries no longer
    /// answer the public resolvers.
    function test_primaryOfGoesEmptyWhenTheRulesNoLongerAllowTheName() public {
        _stage("123", "octo-cat", alice, 100);
        vm.prank(alice);
        _claim(GITHUB, true);
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

        _stage("123", "alice", bob, 100);
        vm.prank(bob);
        _claim(GITHUB, false);

        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(names.resolveHandle(GITHUB, "alice"), bob);
    }

    // ─── Proof versions ─────────────────────────────────────────────
    //
    // A platform's proof can change shape without the account behind it
    // changing — X gaining OIDC, say. Both formats have to be accepted while
    // users migrate, so the Proof Verifier keys its verifiers by version and
    // the keyspace is not keyed at all.

    /// A name belongs to the account that proved it, not to the format the
    /// proof was written in. Removing a version from the Supported Version Set
    /// must not unbind anybody.
    function test_retiringAVersionLeavesItsNamesResolving() public {
        _bind(alice, "123", "alice", 100);

        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));

        assertEq(names.resolveHandle(X, "alice"), alice, "the name went with the format");
        assertEq(names.resolveId(X, "123"), alice);
    }

    /// Which ceremony version proved a binding is logged and never stored.
    /// By the time anybody asks, the proof has happened and the effect has
    /// been applied; the question is an operator's, and the log answers it.
    /// The binding itself is an owner and a watermark, nothing more.
    function test_theLogRecordsWhichCeremonyVersionProvedIt() public {
        StubPlatformVerifier v2 = new StubPlatformVerifier(X, 0);
        vm.prank(owner);
        proofVerifier.setVerifier(X, 2, IPlatformVerifier(address(v2)));

        _stage("456", "bob", bob, 100);
        v2.set("456", "bob");
        v2.setObservedAt(100);
        vm.recordLogs();

        bytes memory payload = _payload(2);
        vm.prank(bob);
        names.claim(X, 2, payload, false);

        (address idOwner, uint64 idAt) = names.byId(IdentityNodes.idNode(X, "456"));
        (address handleOwner, uint64 handleAt) = names.byHandle(IdentityNodes.handleNode(X, "bob"));
        assertEq(idOwner, bob, "the id node");
        assertEq(handleOwner, bob, "the handle node");
        assertEq(idAt, 100);
        assertEq(handleAt, 100);

        (, uint16 logged) = _lastBind();
        assertEq(logged, 2, "the log an indexer reads");
    }

    // ─── A platform is not usable until it can verify ───────────────

    /// Between `setPlatform` and `setVerifier` a platform owns a keyspace and
    /// can verify nothing. Answering `address(0)` there would tell a caller
    /// "nobody holds this name" about a platform that is not wired yet.
    function test_aPlatformWithoutAVerifierDoesNotResolve() public {
        bytes32 fresh = keccak256("fresh");
        vm.prank(owner);
        names.setPlatform(fresh, HandleVectors.rulesFor(X));

        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, fresh));
        names.resolveId(fresh, "123");

        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, fresh));
        names.resolveHandle(fresh, "alice");

        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, fresh));
        names.resolvePair(fresh, "alice", "123");
    }

    /// And claiming says the same thing, rather than naming a version the
    /// caller never chose. The keyspace exists here, so the Consumer lets the
    /// claim through and the Proof Verifier is the one with nothing to
    /// dispatch to.
    function test_claimingAPlatformWithoutAVerifierIsRefused() public {
        bytes32 fresh = keccak256("fresh");
        vm.prank(owner);
        names.setPlatform(fresh, HandleVectors.rulesFor(X));

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, fresh, V1));
        _claim(fresh, false);
    }

    /// `setPlatform` writes field-wise now, so a rules change must leave the
    /// platform exactly as wired as it was. Reintroducing the whole-struct
    /// assignment would unconfigure every platform it touched.
    function test_changingTheRulesLeavesThePlatformWired() public {
        HandleNormalizer.Rules memory narrowed = HandleVectors.rulesFor(X);
        narrowed.maxLength = 12;
        vm.prank(owner);
        names.setPlatform(X, narrowed);

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, false);
        assertEq(names.resolveHandle(X, "alice"), alice);
    }

    /// A retired handle has no owner and keeps its watermark, so a proof
    /// older than the one that retired it cannot take the node back.
    function test_aRetiredHandleHasNoOwnerAndKeepsItsWatermark() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        (address ownerOf, uint64 at) = names.byHandle(IdentityNodes.handleNode(X, "alice"));
        assertEq(ownerOf, address(0), "the handle was retired");
        assertEq(at, 100, "the watermark stays");
    }

    // ─── Ownership ──────────────────────────────────────────────────

    /// The owner has no privileged path to a binding. It obeys the same target
    /// rule as anybody else, so holding the owner key does not let it spend a
    /// proof that names a different address.
    function test_theOwnerHasNoPrivilegedPathToABinding() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", alice, 200);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, alice, owner));
        _claim(X, false);

        assertEq(names.resolveId(X, "123"), alice, "the binding moved");
    }

    /// Configuring a platform is the whole of the owner's power here, and it
    /// reaches no existing binding. Replacing the verifier a version dispatches
    /// to must not disturb a name that the previous one's proof established.
    function test_reconfiguringAPlatformLeavesBindingsAlone() public {
        _bind(alice, "123", "alice", 100);

        StubPlatformVerifier replacement = new StubPlatformVerifier(X, 0);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(replacement)));

        assertEq(names.resolveId(X, "123"), alice);
        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(address(proofVerifier.verifierOf(X, V1)), address(replacement));
    }

    function test_onlyTheOwnerConfiguresAPlatform() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        names.setPlatform(X, HandleVectors.rulesFor(X));
    }
}
