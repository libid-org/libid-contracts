// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {HandleResolver, OffchainLookup} from "../HandleResolver.sol";
import {IExtendedResolver} from "../IExtendedResolver.sol";

/// @notice The resolver, against the protocol a wallet actually speaks.
contract HandleResolverTest is Test {
    HandleResolver internal resolver;

    address internal owner = makeAddr("owner");
    uint256 internal signerKey = 0xA11CE;
    address internal signer;
    uint256 internal impostorKey = 0xBAD;

    string internal constant URL = "https://gw.handles.link/{sender}/{data}.json";

    /// `alice.x.handles.link` in DNS wire format.
    bytes internal name = hex"05616c69636501780768616e646c6573046c696e6b00";
    /// `addr(node, 0x80000000 | 8453)` — Base, per ENSIP-11.
    bytes internal data = abi.encodeWithSignature("addr(bytes32,uint256)", bytes32(uint256(1)), uint256(0x80002105));

    function setUp() public {
        signer = vm.addr(signerKey);
        string[] memory urls = new string[](1);
        urls[0] = URL;
        address[] memory signers = new address[](1);
        signers[0] = signer;
        resolver = new HandleResolver(owner, urls, signers);
    }

    /// What the gateway does, reproduced here so the test proves the two agree
    /// rather than assuming it.
    function _sign(uint256 key, bytes memory request, bytes memory result, uint64 expires)
        internal
        view
        returns (bytes memory response)
    {
        bytes32 digest = resolver.makeSignatureHash(address(resolver), expires, request, result);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encode(result, expires, abi.encodePacked(r, s, v));
    }

    // ─── The protocol ───────────────────────────────────────────────

    /// A wallet will not hand a wildcard name to a resolver that does not say
    /// it speaks ENSIP-10, so this answer is what makes the whole scheme reach
    /// this contract at all.
    function test_itAnnouncesWildcardResolution() public view {
        assertTrue(resolver.supportsInterface(0x9061b923), "ENSIP-10 not announced");
        assertTrue(resolver.supportsInterface(0x01ffc9a7), "ERC-165 not announced");
        assertFalse(resolver.supportsInterface(0xdeadbeef));
    }

    /// `resolve` always reverts, and that IS the protocol: the revert carries
    /// the endpoints, which is why nothing has to be registered with a wallet.
    function test_resolveRevertsWithTheEndpointsAndTheQuery() public {
        bytes memory expected = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);

        string[] memory urls = new string[](1);
        urls[0] = URL;

        vm.expectRevert(
            abi.encodeWithSelector(
                OffchainLookup.selector, address(resolver), urls, expected, resolver.resolveWithProof.selector, expected
            )
        );
        resolver.resolve(name, data);
    }

    /// The whole round trip: the gateway answers, signs, and the second call
    /// returns the record.
    function test_aSignedAnswerResolves() public view {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        bytes memory response = _sign(signerKey, request, result, uint64(block.timestamp + 300));

        assertEq(resolver.resolveWithProof(response, request), result);
    }

    // ─── What the signature is for ──────────────────────────────────

    function test_anAnswerNobodyInTheSetSignedIsRefused() public {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        bytes memory response = _sign(impostorKey, request, result, uint64(block.timestamp + 300));

        vm.expectRevert(abi.encodeWithSelector(HandleResolver.UntrustedSigner.selector, vm.addr(impostorKey)));
        resolver.resolveWithProof(response, request);
    }

    /// Seizing the endpoint is not enough — this is the property that lets the
    /// gateway URL be the least sensitive key in the system.
    function test_theResultCannotBeChangedAfterSigning() public {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory response = _sign(signerKey, request, abi.encode(address(0xBEEF)), uint64(block.timestamp + 300));

        (, uint64 expires, bytes memory sig) = abi.decode(response, (bytes, uint64, bytes));
        bytes memory tampered = abi.encode(abi.encode(address(0xDEAD)), expires, sig);

        // Recovers somebody else entirely — nobody in the set.
        vm.expectPartialRevert(HandleResolver.UntrustedSigner.selector);
        resolver.resolveWithProof(tampered, request);
    }

    /// An answer for one name must not resolve another.
    function test_anAnswerCannotBeReusedForAnotherQuery() public {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory response = _sign(signerKey, request, abi.encode(address(0xBEEF)), uint64(block.timestamp + 300));

        bytes memory otherName = hex"03626f6201780768616e646c6573046c696e6b00"; // bob.x.handles.link
        bytes memory otherRequest = abi.encodeWithSelector(IExtendedResolver.resolve.selector, otherName, data);

        vm.expectPartialRevert(HandleResolver.UntrustedSigner.selector);
        resolver.resolveWithProof(response, otherRequest);
    }

    /// And must not resolve against a different resolver, which is why the
    /// target is inside the hash.
    function test_anAnswerCannotBeReusedAgainstAnotherResolver() public {
        string[] memory urls = new string[](1);
        urls[0] = URL;
        address[] memory signers = new address[](1);
        signers[0] = signer;
        HandleResolver other = new HandleResolver(owner, urls, signers);

        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        uint64 expires = uint64(block.timestamp + 300);

        // Signed for `resolver`, replayed at `other`.
        bytes memory response = _sign(signerKey, request, result, expires);
        vm.expectPartialRevert(HandleResolver.UntrustedSigner.selector);
        other.resolveWithProof(response, request);
    }

    function test_anExpiredAnswerIsRefused() public {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory response = _sign(signerKey, request, abi.encode(address(0xBEEF)), expires);

        vm.warp(uint256(expires) + 1);
        vm.expectRevert(abi.encodeWithSelector(HandleResolver.SignatureExpired.selector, expires, block.timestamp));
        resolver.resolveWithProof(response, request);
    }

    /// The boundary itself, because only `expires + 1` was exercised: flip
    /// `<` to `<=` and every answer becomes unusable in the block its own
    /// deadline names — a failure that would surface in production, on a
    /// fraction of calls, looking like gateway flakiness.
    function test_anAnswerIsStillGoodInTheBlockItExpires() public view {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        bytes memory response = _sign(signerKey, request, result, uint64(block.timestamp));

        assertEq(resolver.resolveWithProof(response, request), result);
    }

    /// `expires` is the gateway's to choose, so the contract bounds it. Without
    /// this a captured blob stays valid past any rename, and replaying it
    /// returns the wallet the name USED to hold.
    function test_anAnswerCannotClaimAnUnboundedLifetime() public {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        uint64 forever = type(uint64).max;
        bytes memory response = _sign(signerKey, request, result, forever);

        vm.expectRevert(
            abi.encodeWithSelector(
                HandleResolver.DeadlineTooFar.selector, forever, block.timestamp + resolver.MAX_LIFETIME()
            )
        );
        resolver.resolveWithProof(response, request);
    }

    /// And the ceiling itself is usable, not merely present.
    function test_anAnswerAtTheCeilingIsAccepted() public view {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        bytes memory response = _sign(signerKey, request, result, uint64(block.timestamp + resolver.MAX_LIFETIME()));

        assertEq(resolver.resolveWithProof(response, request), result);
    }

    // ─── Configuration ──────────────────────────────────────────────

    function test_onlyTheOwnerConfigures() public {
        string[] memory urls = new string[](1);
        urls[0] = "https://elsewhere/{sender}/{data}.json";
        address mallory = makeAddr("mallory");

        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, mallory));
        resolver.setUrls(urls);

        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, mallory));
        resolver.setSigner(vm.addr(impostorKey), true);
    }

    /// Rotation adds before it removes, or answers already in flight start
    /// failing.
    function test_theSignerSetRotates() public {
        address next = vm.addr(impostorKey);
        vm.startPrank(owner);
        resolver.setSigner(next, true);
        assertTrue(resolver.signers(next));
        assertTrue(resolver.signers(signer), "the old signer was dropped too early");
        resolver.setSigner(signer, false);
        vm.stopPrank();

        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        assertEq(
            resolver.resolveWithProof(_sign(impostorKey, request, result, uint64(block.timestamp + 60)), request),
            result
        );

        // Built BEFORE the expectation: `_sign` calls the resolver, and that
        // call would consume it.
        bytes memory stale = _sign(signerKey, request, result, uint64(block.timestamp + 60));
        vm.expectRevert(abi.encodeWithSelector(HandleResolver.UntrustedSigner.selector, signer));
        resolver.resolveWithProof(stale, request);
    }

    /// A resolver with no endpoint would revert `OffchainLookup` with an empty
    /// list, which a client reports as an opaque failure.
    function test_aResolverWithNoEndpointSaysSo() public {
        string[] memory none = new string[](0);
        vm.prank(owner);
        resolver.setUrls(none);

        vm.expectRevert(HandleResolver.NoUrls.selector);
        resolver.resolve(name, data);
    }

    /// The signing scheme, recomputed the way `ensdomains/offchain-resolver`
    /// does it, so the claim that an off-the-shelf gateway works here is a
    /// test rather than a sentence in a commit message.
    ///
    /// The reference carries `abi.encode(callData, address(this))` in
    /// `extraData` and recovers the target by decoding it; this contract
    /// passes `callData` alone and names `address(this)` directly. Different
    /// bytes travel, but the gateway never sees `extraData` -- it is handed
    /// `sender` and `data` by ERC-3668 -- and the four values that reach the
    /// hash are the same four. Change either side and this fails.
    function test_theSigningSchemeMatchesTheEnsReference() public view {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        uint64 expires = uint64(block.timestamp + 300);

        // SignatureVerifier.makeSignatureHash, inlined.
        bytes32 expectedHash =
            keccak256(abi.encodePacked(hex"1900", address(resolver), expires, keccak256(request), keccak256(result)));

        assertEq(resolver.makeSignatureHash(address(resolver), expires, request, result), expectedHash);
    }

    // ─── What the gateway may send ──────────────────────────────────

    /// The response is bytes from an untrusted HTTP endpoint, decoded before
    /// anything is checked. A gateway that is broken, hostile, or simply
    /// serving another protocol must not produce a return value.
    ///
    /// `abi.decode` reverts on a malformed word, so the guarantee already
    /// holds — this pins it, because the day someone replaces the decode with
    /// hand-rolled slicing is the day it stops holding silently.
    function test_aMalformedGatewayResponseCannotReturnAnything() public {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);

        bytes[] memory junk = new bytes[](4);
        junk[0] = hex"";
        junk[1] = hex"deadbeef";
        junk[2] = abi.encode(uint256(1)); // one word, three expected
        junk[3] = abi.encode(bytes("x"), uint64(block.timestamp + 300)); // signature missing

        for (uint256 i = 0; i < junk.length; i++) {
            // `abi.decode` reverts with no data, so there is no selector to
            // name here: the property is that nothing returns.
            vm.expectRevert();
            resolver.resolveWithProof(junk[i], request);
        }
    }

    /// The check that matters is set membership, so the signature has to be
    /// one `recover` accepts.
    ///
    /// This asserted nothing before: 65 zero bytes give `v == 0`, which OZ's
    /// `ECDSA.recover` rejects with `ECDSAInvalidSignature` before the signer
    /// lookup runs at all — so a bare `expectRevert` passed even with the
    /// membership check deleted. A real signature from a key nobody trusts,
    /// asserted against this contract's OWN error, is the property.
    function test_aValidSignatureFromAnUntrustedKeyIsRefused() public {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory result = abi.encode(address(0xBEEF));
        bytes memory response = _sign(impostorKey, request, result, uint64(block.timestamp + 300));

        vm.expectRevert(abi.encodeWithSelector(HandleResolver.UntrustedSigner.selector, vm.addr(impostorKey)));
        resolver.resolveWithProof(response, request);
    }

    /// And the malformed case, kept but named for what it is: bytes that never
    /// reach the signer set because recovery itself refuses them.
    function test_aSignatureRecoveryCannotAcceptIsRefusedEarlier() public {
        bytes memory request = abi.encodeWithSelector(IExtendedResolver.resolve.selector, name, data);
        bytes memory response = abi.encode(abi.encode(address(0xBEEF)), uint64(block.timestamp + 300), new bytes(65));

        vm.expectRevert(ECDSA.ECDSAInvalidSignature.selector);
        resolver.resolveWithProof(response, request);
    }

    /// Deploying with no endpoint is allowed: the ENS name and the resolver are
    /// set in one `proveAndClaimWithResolver`, and the gateway may not be up
    /// yet. `NoUrls` at resolve time is where that becomes visible, and
    /// `setUrls` is the repair.
    function test_aResolverMayBeDeployedBeforeItsGatewayExists() public {
        string[] memory none = new string[](0);
        address[] memory signers = new address[](1);
        signers[0] = signer;

        HandleResolver bare = new HandleResolver(owner, none, signers);
        assertEq(bare.urlCount(), 0);

        vm.expectRevert(HandleResolver.NoUrls.selector);
        bare.resolve(name, data);

        string[] memory one = new string[](1);
        one[0] = URL;
        vm.prank(owner);
        bare.setUrls(one);
        assertEq(bare.urlCount(), 1);
    }

    function test_ownershipCannotBeRenounced() public {
        vm.prank(owner);
        vm.expectRevert("renounce disabled");
        resolver.renounceOwnership();
    }
}
