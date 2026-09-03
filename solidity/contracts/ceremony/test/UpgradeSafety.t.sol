// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {CeremonyProofVerifier} from "../CeremonyProofVerifier.sol";
import {NotaryService} from "../NotaryService.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";
import {GitHubPlatformVerifier} from "../GitHubPlatformVerifier.sol";
import {GooglePlatformVerifier, IJwksRoots} from "../GooglePlatformVerifier.sol";
import {INotaryService} from "../INotaryService.sol";
import {IHonkVerifier} from "../PlatformVerifierBase.sol";
import {IPlatformVerifier} from "../IPlatformVerifier.sol";
import {IProofVerifier} from "../IProofVerifier.sol";
import {IdentityNames} from "../../identity/IdentityNames.sol";
import {IdentityJwksRoots} from "../../identity/IdentityJwksRoots.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {HandleNormalizer} from "../../identity/HandleNormalizer.sol";
import {IdentityNodes} from "../../identity/IdentityNodes.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";

contract RHonk is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract RRoots is IJwksRoots {
    function trustedHashExpiresAt(bytes32) external pure returns (uint256) {
        return 0;
    }
}

/// @notice Every deployed contract survives an upgrade, refuses one from a
///         stranger, and cannot be initialized twice or on its implementation.
contract UpgradeSafetyTest is Test {
    address constant OWNER = address(0xA11CE);
    address constant STRANGER = address(0xBAD);
    address constant NOTARY = address(0x7A0);
    bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 constant REENTRANCY_SLOT = 0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;
    bytes32 constant NAMES_ROOT = 0x064503501234cc9c6e116cf4a84c07475158dabb6a3dcee437a89227e23bf200;
    bytes32 constant X = HandleVectors.PLATFORM_X;

    function _slot(string memory ns) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(keccak256(bytes(ns))) - 1)) & ~bytes32(uint256(0xff));
    }

    function test_erc7201SlotsMatchSource() public pure {
        assertEq(
            _slot("libid.storage.CeremonyProofVerifier"),
            0x128443dce113885ee8c5806bf38d25bc0d69e6c9a5ceda8792c21c106d531700
        );
        assertEq(
            _slot("libid.storage.NotaryService"), 0x7e0f45e5fb68069046082b9a29aa418cbadf43bb1025c0e2debddab14853f800
        );
        assertEq(
            _slot("libid.storage.PlatformVerifier"), 0xfd6bfa775d4a790b2a39afc6490b76805795bc7d3963618ec6b2ee0a55986900
        );
        assertEq(
            _slot("libid.storage.GooglePlatformVerifier"),
            0x92a7c997eeb454ceeeb8ef2d99ba7d4b830287ff966f129f9049c466a8342400
        );
        assertEq(_slot("libid.storage.IdentityNames"), NAMES_ROOT);
        assertEq(
            _slot("libid.storage.IdentityJwksRoots"), 0x1aceb787a5cb65251c62e0afbe6fbce480e0d1c9636ff7b90cdca2969527ef00
        );
    }

    function _implOf(address proxy) internal view returns (address) {
        return address(uint160(uint256(vm.load(proxy, IMPL_SLOT))));
    }

    function _expectNotOwner() internal {
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, STRANGER));
    }

    // ─── CeremonyProofVerifier ──────────────────────────────────────

    function test_upgrade_CeremonyProofVerifier() public {
        CeremonyProofVerifier impl = new CeremonyProofVerifier();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(OWNER);

        CeremonyProofVerifier pv = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))))
        );
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pv.initialize(OWNER);

        StubPlatformVerifier s = new StubPlatformVerifier(X, 0);
        vm.prank(OWNER);
        pv.setVerifier(X, 1, IPlatformVerifier(address(s)));

        CeremonyProofVerifier impl2 = new CeremonyProofVerifier();
        _expectNotOwner();
        pv.upgradeToAndCall(address(impl2), "");
        vm.prank(OWNER);
        pv.upgradeToAndCall(address(impl2), "");

        assertEq(_implOf(address(pv)), address(impl2));
        assertEq(address(pv.verifierOf(X, 1)), address(s));
        assertTrue(pv.verifiesPlatform(X));
        assertEq(pv.owner(), OWNER);
    }

    // ─── NotaryService ──────────────────────────────────────────────

    function _notaryService() internal returns (NotaryService ns) {
        NotaryService impl = new NotaryService();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(OWNER, NOTARY, 7);
        ns = NotaryService(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(NotaryService.initialize, (OWNER, NOTARY, 7))))
        );
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        ns.initialize(OWNER, NOTARY, 7);
    }

    function test_upgrade_NotaryService() public {
        NotaryService ns = _notaryService();
        vm.deal(address(ns), 3 ether);
        NotaryService impl2 = new NotaryService();
        _expectNotOwner();
        ns.upgradeToAndCall(address(impl2), "");
        vm.prank(OWNER);
        ns.upgradeToAndCall(address(impl2), "");
        assertEq(_implOf(address(ns)), address(impl2));
        assertEq(ns.fee(), 7);
        assertTrue(ns.isTrustedNotary(NOTARY));
        assertEq(address(ns).balance, 3 ether);
        assertEq(ns.owner(), OWNER);
    }

    // ─── X / GitHub ─────────────────────────────────────────────────

    function test_upgrade_XPlatformVerifier() public {
        NotaryService ns = _notaryService();
        RHonk honk = new RHonk();
        XPlatformVerifier impl = new XPlatformVerifier();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(OWNER, ns, honk, address(honk).codehash, 3600, 300, 300);
        XPlatformVerifier v = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        XPlatformVerifier.initialize, (OWNER, ns, honk, address(honk).codehash, 3600, 300, 300)
                    )
                )
            )
        );
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        v.initialize(OWNER, ns, honk, address(honk).codehash, 3600, 300, 300);

        XPlatformVerifier impl2 = new XPlatformVerifier();
        _expectNotOwner();
        v.upgradeToAndCall(address(impl2), "");
        vm.prank(OWNER);
        v.upgradeToAndCall(address(impl2), "");
        assertEq(_implOf(address(v)), address(impl2));
        assertEq(v.notaryService(), address(ns));
        assertEq(v.honkVerifier(), address(honk));
        assertEq(v.honkVerifierCodehash(), address(honk).codehash);
        (uint64 a, uint64 b, uint64 c) = v.protocolParameters();
        assertEq(a, 3600);
        assertEq(b, 300);
        assertEq(c, 300);
        assertEq(v.quote(), 14);
        assertEq(v.owner(), OWNER);
    }

    function test_upgrade_GitHubPlatformVerifier() public {
        NotaryService ns = _notaryService();
        RHonk honk = new RHonk();
        GitHubPlatformVerifier impl = new GitHubPlatformVerifier();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(OWNER, ns, honk, address(honk).codehash, 3600, 300, 300);
        GitHubPlatformVerifier v = GitHubPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        GitHubPlatformVerifier.initialize, (OWNER, ns, honk, address(honk).codehash, 3600, 300, 300)
                    )
                )
            )
        );
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        v.initialize(OWNER, ns, honk, address(honk).codehash, 3600, 300, 300);

        GitHubPlatformVerifier impl2 = new GitHubPlatformVerifier();
        _expectNotOwner();
        v.upgradeToAndCall(address(impl2), "");
        vm.prank(OWNER);
        v.upgradeToAndCall(address(impl2), "");
        assertEq(_implOf(address(v)), address(impl2));
        assertEq(v.notaryService(), address(ns));
        assertEq(v.honkVerifier(), address(honk));
        assertEq(v.quote(), 14);
        assertEq(v.owner(), OWNER);
    }

    // ─── Google ─────────────────────────────────────────────────────

    function test_upgrade_GooglePlatformVerifier() public {
        RHonk honk = new RHonk();
        RRoots roots = new RRoots();
        GooglePlatformVerifier impl = new GooglePlatformVerifier();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(OWNER, INotaryService(address(0)), honk, address(honk).codehash, 7200, roots);
        GooglePlatformVerifier v = GooglePlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        GooglePlatformVerifier.initialize,
                        (OWNER, INotaryService(address(0)), honk, address(honk).codehash, 7200, roots)
                    )
                )
            )
        );
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        v.initialize(OWNER, INotaryService(address(0)), honk, address(honk).codehash, 7200, roots);

        GooglePlatformVerifier impl2 = new GooglePlatformVerifier();
        _expectNotOwner();
        v.upgradeToAndCall(address(impl2), "");
        vm.prank(OWNER);
        v.upgradeToAndCall(address(impl2), "");
        assertEq(_implOf(address(v)), address(impl2));
        assertEq(v.jwksRoots(), address(roots));
        assertEq(v.honkVerifier(), address(honk));
        assertEq(v.notaryService(), address(0));
        (,, uint64 c) = v.protocolParameters();
        assertEq(c, 7200);
        assertEq(v.owner(), OWNER);
    }

    // ─── IdentityJwksRoots ──────────────────────────────────────────

    function test_upgrade_IdentityJwksRoots() public {
        INotaryService ns = INotaryService(address(_notaryService()));
        IdentityJwksRoots impl = new IdentityJwksRoots();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(OWNER, ns);
        IdentityJwksRoots r = IdentityJwksRoots(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityJwksRoots.initialize, (OWNER, ns))))
        );
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        r.initialize(OWNER, ns);

        IdentityJwksRoots impl2 = new IdentityJwksRoots();
        _expectNotOwner();
        r.upgradeToAndCall(address(impl2), "");
        vm.prank(OWNER);
        r.upgradeToAndCall(address(impl2), "");
        assertEq(_implOf(address(r)), address(impl2));
        assertEq(r.notaryService(), address(ns));
        assertEq(r.quoteRotation(), 7);
        assertTrue(r.needsRotation());
        assertEq(r.owner(), OWNER);
    }

    // ─── IdentityNames ──────────────────────────────────────────────

    IdentityNames names;
    CeremonyProofVerifier pv;
    StubPlatformVerifier stub;
    address alice = makeAddr("alice");

    function _names() internal {
        IdentityNames impl = new IdentityNames();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(OWNER);
        names =
            IdentityNames(address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityNames.initialize, (OWNER)))));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        names.initialize(OWNER);
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        pv = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))))
        );
        stub = new StubPlatformVerifier(X, 0);
        vm.startPrank(OWNER);
        names.setProofVerifier(IProofVerifier(address(pv)));
        pv.setVerifier(X, 1, IPlatformVerifier(address(stub)));
        vm.stopPrank();
        vm.warp(2_000_000_000);
    }

    function _claimAs(address who, uint256 nonce) internal {
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(nonce),
                transactionData: abi.encode(who)
            })
        );
        vm.prank(who);
        names.claim(X, 1, payload, true);
    }

    function test_upgrade_IdentityNames() public {
        _names();
        vm.prank(OWNER);
        names.setPlatform(X, HandleVectors.rulesFor(X));
        _claimAs(alice, 1);
        bytes32 digest = stub.lastDigest();

        IdentityNames impl2 = new IdentityNames();
        _expectNotOwner();
        names.upgradeToAndCall(address(impl2), "");
        vm.prank(OWNER);
        names.upgradeToAndCall(address(impl2), "");
        assertEq(_implOf(address(names)), address(impl2));

        assertEq(names.resolveId(X, "2244994945"), alice);
        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(names.primaryOf(alice, X), "alice");
        assertTrue(names.digestSpent(digest));
        assertEq(address(names.proofVerifier()), address(pv));
        assertEq(names.owner(), OWNER);
        // and the contract still works after the upgrade (newer watermark)
        stub.setObservedAt(1_780_000_000);
        _claimAs(alice, 2);
        (, uint64 at) = names.byId(IdentityNodes.idNode(X, "2244994945"));
        assertEq(at, 1_780_000_000);
    }

    // The two Platform layouts, replicated so the slot arithmetic is measured
    // rather than asserted from memory.
    struct MainPlatform {
        HandleNormalizer.Rules rules;
        uint32 latestVersion;
        bool configured;
    }

    struct PrPlatform {
        HandleNormalizer.Rules rules;
        bool configured;
    }

    MainPlatform mainP;
    PrPlatform prP;

    /// Emulate the storage a main-deployed IdentityNames proxy holds for a
    /// configured platform, then read it through the PR implementation.
    function _emulateMainPlatform(uint32 latestVersion, bool configured) internal {
        bytes32 entry = keccak256(abi.encode(X, uint256(NAMES_ROOT) + 3));
        HandleNormalizer.Rules memory r = HandleVectors.rulesFor(X);
        uint256 rulesWord = uint256(r.maxLength) | (r.stripLeadingAt ? 1 << 16 : 0) | (r.isEmail ? 1 << 24 : 0)
            | (r.allowUnderscore ? 1 << 32 : 0) | (r.allowHyphen ? 1 << 40 : 0);
        vm.store(address(names), entry, bytes32(rulesWord));
        uint256 w = uint256(latestVersion) | (configured ? uint256(1) << 32 : 0);
        vm.store(address(names), bytes32(uint256(entry) + 1), bytes32(w));
    }

    function _claimExternal(address who, uint256 nonce) external {
        _claimAs(who, nonce);
    }

    /// Binding lost `version` (uint32 at byte offset 28). Stale bits in that
    /// word are ignored by the PR's reads, and a fresh write leaves them as-is.
    function test_bindingStaleVersionWordIsIgnored() public {
        _names();
        vm.prank(OWNER);
        names.setPlatform(X, HandleVectors.rulesFor(X));
        bytes32 idNode = IdentityNodes.idNode(X, "2244994945");
        bytes32 slot = keccak256(abi.encode(idNode, uint256(NAMES_ROOT) + 0));
        address bob = address(0xB0B);
        uint256 word = uint256(uint160(bob)) | (uint256(1_900_000_000) << 160) | (uint256(7) << 224);
        vm.store(address(names), slot, bytes32(word));
        (address o, uint64 at) = names.byId(idNode);
        assertEq(o, bob);
        assertEq(at, 1_900_000_000);
        stub.setObservedAt(1_950_000_000);
        _claimAs(alice, 1);
        bytes32 afterWord = vm.load(address(names), slot);
        emit log_named_bytes32("byId word after fresh write", afterWord);
        (o, at) = names.byId(idNode);
        assertEq(o, alice);
        assertEq(at, 1_950_000_000);
        // stale version bits (byte 28..31) survive a member-wise struct write?
        emit log_named_uint("stale version bits after write", uint256(afterWord) >> 224);
    }
}
