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
import {GooglePlatformVerifier, IGoogleJwtRoots} from "../GooglePlatformVerifier.sol";
import {INotaryService} from "../INotaryService.sol";
import {IHonkVerifier} from "../PlatformVerifierBase.sol";
import {IPlatformVerifier} from "../IPlatformVerifier.sol";
import {IProofVerifier} from "../IProofVerifier.sol";
import {IdentityNames} from "../../identity/IdentityNames.sol";
import {GoogleJwtRoots} from "../GoogleJwtRoots.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {IdentityNodes} from "../../identity/IdentityNodes.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {AttestationBuilder} from "./AttestationBuilder.sol";

contract RHonk is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract RRoots is IGoogleJwtRoots {
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
    bytes32 constant ROOTS_ROOT = 0x7f78ff13201a03086d4b08e3085224c34a9fc247d0f67d11acd0db52976eb300;
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
        assertEq(_slot("libid.storage.GoogleJwtRoots"), ROOTS_ROOT);
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
        assertEq(v.jwtRoots(), address(roots));
        assertEq(v.honkVerifier(), address(honk));
        assertEq(v.notaryService(), address(0));
        (,, uint64 c) = v.protocolParameters();
        assertEq(c, 7200);
        assertEq(v.owner(), OWNER);
    }

    // ─── GoogleJwtRoots ──────────────────────────────────────────

    function test_upgrade_GoogleJwtRoots() public {
        INotaryService ns = INotaryService(address(_notaryService()));
        GoogleJwtRoots impl = new GoogleJwtRoots();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(OWNER, ns);
        GoogleJwtRoots r = GoogleJwtRoots(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(GoogleJwtRoots.initialize, (OWNER, ns))))
        );
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        r.initialize(OWNER, ns);

        // Two rotations land BEFORE the upgrade -- two different one-key
        // readings, so BOTH generations hold state -- and what has to survive
        // is real state in the namespaced slots rather than the empty list
        // initialize left behind.
        uint256 notaryKey = 0xA11CE5;
        vm.prank(OWNER);
        NotaryService(address(ns)).setNotary(vm.addr(notaryKey), true);
        vm.deal(address(this), 1 ether);
        vm.warp(1_770_000_000);
        uint64 first = uint64(vm.getBlockTimestamp());
        bytes memory attested = _jwksReading(first, JWKS_MODULUS);
        r.rotate{value: 7}(attested, _signed(notaryKey, attested));
        vm.warp(first + 60);
        uint64 second = uint64(vm.getBlockTimestamp());
        attested = _jwksReading(second, _otherModulus());
        r.rotate{value: 7}(attested, _signed(notaryKey, attested));

        (GoogleJwtRoots.Generation memory current, GoogleJwtRoots.Generation memory previous) = r.currentKeys();
        assertEq(current.observedAt, second, "the second rotation landed");
        assertEq(previous.observedAt, first, "the first rotation was kept");
        assertEq(current.moduli.length, 1);
        assertEq(previous.moduli.length, 1);
        bytes32 newer = current.moduli[0];
        bytes32 older = previous.moduli[0];
        assertTrue(newer != older, "two different keys");
        uint256 lifetime = r.READING_LIFETIME();

        // The layout those two generations sit in, pinned word by word.
        // `notary` is word 0 of the namespace; a Generation is two words --
        // its stamp, then the length word of its dynamic array, whose
        // elements hang off keccak256(that word's slot) -- so `current` is
        // words 1-2 and `previous` words 3-4. A field added to Generation
        // moves `previous`, and an upgraded implementation would then read
        // the old generation's stamp as the new field: this is where that
        // has to fail, loudly, before any upgrade does.
        uint256 base = uint256(ROOTS_ROOT);
        assertEq(uint256(vm.load(address(r), bytes32(base))), uint256(uint160(address(ns))), "word 0: notary");
        assertEq(uint256(vm.load(address(r), bytes32(base + 1))), second, "word 1: current.observedAt");
        assertEq(uint256(vm.load(address(r), bytes32(base + 2))), 1, "word 2: current.moduli.length");
        assertEq(vm.load(address(r), keccak256(abi.encode(base + 2))), newer, "current.moduli[0]");
        assertEq(uint256(vm.load(address(r), bytes32(base + 3))), first, "word 3: previous.observedAt");
        assertEq(uint256(vm.load(address(r), bytes32(base + 4))), 1, "word 4: previous.moduli.length");
        assertEq(vm.load(address(r), keccak256(abi.encode(base + 4))), older, "previous.moduli[0]");

        GoogleJwtRoots impl2 = new GoogleJwtRoots();
        _expectNotOwner();
        r.upgradeToAndCall(address(impl2), "");
        vm.prank(OWNER);
        r.upgradeToAndCall(address(impl2), "");
        assertEq(_implOf(address(r)), address(impl2));
        assertEq(r.notaryService(), address(ns));
        assertEq(r.quoteRotation(), 7);
        assertEq(r.owner(), OWNER);
        assertEq(r.trustedHashExpiresAt(newer), second + lifetime, "the current generation was lost");
        assertEq(r.trustedHashExpiresAt(older), first + lifetime, "the previous generation was lost");
        (current, previous) = r.currentKeys();
        assertEq(current.observedAt, second);
        assertEq(current.moduli.length, 1);
        assertEq(current.moduli[0], newer);
        assertEq(previous.observedAt, first);
        assertEq(previous.moduli.length, 1);
        assertEq(previous.moduli[0], older);
        assertEq(r.freshestObservedAt(), second);
        assertFalse(r.needsRotation());
    }

    function _signed(uint256 key, bytes memory attested) internal pure returns (bytes memory) {
        (uint8 v, bytes32 sigR, bytes32 sigS) =
            vm.sign(key, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(attested))));
        return abi.encodePacked(sigR, sigS, v);
    }

    /// One notarized reading of Google's JWKS carrying one key: the request
    /// and the response revealed whole, nothing committed.
    function _jwksReading(uint64 createdAt, string memory modulus) internal pure returns (bytes memory) {
        bytes memory sent = "GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.com\r\nconnection: close\r\n\r\n";
        bytes memory body = abi.encodePacked('{"keys":[{"kid":"k","n":"', modulus, '","e":"AQAB"}]}');
        bytes memory received =
            abi.encodePacked("HTTP/1.1 200 OK\r\ncontent-length: ", vm.toString(body.length), "\r\n\r\n", body);
        return AttestationBuilder.encode(keccak256("www.googleapis.com"), createdAt, _whole(sent), _whole(received));
    }

    /// A second 2048-bit modulus: the keeper's vector with its first
    /// character changed -- still 342 characters of base64url, a different
    /// key.
    function _otherModulus() internal pure returns (string memory) {
        bytes memory modulus = bytes(JWKS_MODULUS);
        modulus[0] = "C";
        return string(modulus);
    }

    function _whole(bytes memory transcript) internal pure returns (AttestationBuilder.Direction memory) {
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: transcript})),
            commitments: AttestationBuilder.none(),
            length: uint32(transcript.length)
        });
    }

    /// A 2048-bit modulus in base64url (the keeper's own test vector).
    string internal constant JWKS_MODULUS =
        "BAsSGSAnLjU8Q0pRWF9mbXR7gomQl56lrLO6wcjP1t3k6_L5BQwTGiEoLzY9REtSWWBnbnV8g4qRmJ-mrbS7wsnQ197l7PP6Bg0UGyIpMDc-RUxTWmFob3Z9hIuSmaCnrrW8w8rR2N_m7fT7Bw4VHCMqMTg_Rk1UW2JpcHd-hYyTmqGor7a9xMvS2eDn7vUBCA8WHSQrMjlAR05VXGNqcXh_ho2Um6KpsLe-xczT2uHo7_YCCRAXHiUsMzpBSE9WXWRrcnmAh46VnKOqsbi_xs3U2-Lp8PcDChEYHyYtNDtCSVBXXmVsc3qBiI-WnaSrsrnAx87V3OPq8fgECxIZIA";

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

    function _claimExternal(address who, uint256 nonce) external {
        _claimAs(who, nonce);
    }

    /// `Binding` once carried a `version` (uint32 at byte offset 28). Stale bits
    /// in that word are ignored by the current reads, and a fresh write leaves them as-is.
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
