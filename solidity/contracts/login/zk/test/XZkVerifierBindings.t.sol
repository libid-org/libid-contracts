// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../../Registry.sol";
import {WalletFactory} from "../../WalletFactory.sol";
import {WebWallet} from "../../WebWallet.sol";
import {XZkVerifier, IHonkVerifier} from "../XZkVerifier.sol";
import {IZkSessionVerifier} from "../IZkSessionVerifier.sol";
import {Notary} from "../../../notary/Notary.sol";
import {deployNotary} from "../../../notary/test/DeployNotary.sol";

/// Mock honk verifier — always returns the configured value. Lets us
/// exercise XZkVerifier wiring without a real Honk proof.
contract MockHonkVerifier is IHonkVerifier {
    bool public ret = true;

    function setRet(bool v) external {
        ret = v;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return ret;
    }
}

/// Bindings for the new token-only XZkVerifier. The on-chain check is
/// orthogonal to the actual Honk proof contents — we cover:
///   1. Happy path: notary-signed token+me attestations + matching PI.
///   2. PI walletAddress is returned unchanged (Registry, not verifier, enforces binding).
///   3. Cross-bind revert: differing bearerHash.
///   4. sessionAddr mismatch revert: PI sessionAddr != meAttest.sessionAddr.
///   5. /me request-line structure revert.
///   6. handle not found in recvRevealed revert.
///   7. client_id mismatch revert.
contract XZkVerifierBindingsTest is Test {
    Registry registry;
    WalletFactory factory;
    XZkVerifier verifier;
    MockHonkVerifier honk;

    uint256 constant NOTARY_PK = 0xA001;
    address NOTARY;
    Notary notaryContract;
    address constant OWNER = address(0xA11CE);
    string constant PLATFORM = "api.x.com";
    string constant ENDPOINT = "/2/users/me";
    string constant HANDLE_PREFIX = "\"username\":\"";
    bytes constant X_CLIENT_ID = bytes("dev-client-id-123");

    function setUp() public {
        NOTARY = vm.addr(NOTARY_PK);
        notaryContract = deployNotary(OWNER, NOTARY);

        WebWallet walletImpl = new WebWallet();
        WalletFactory fImpl = new WalletFactory();
        factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl), abi.encodeCall(WalletFactory.initialize, (OWNER, address(walletImpl), address(1)))
                )
            )
        );

        Registry rImpl = new Registry();
        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl),
                    abi.encodeCall(
                        Registry.initialize, (address(notaryContract), address(0xBE), address(factory), OWNER)
                    )
                )
            )
        );

        vm.prank(OWNER);
        factory.setRegistry(address(registry));

        honk = new MockHonkVerifier();
        XZkVerifier xImpl = new XZkVerifier();
        verifier = XZkVerifier(
            address(
                new ERC1967Proxy(
                    address(xImpl),
                    abi.encodeCall(
                        XZkVerifier.initialize,
                        (
                            OWNER,
                            address(notaryContract),
                            IHonkVerifier(address(honk)),
                            X_CLIENT_ID,
                            ENDPOINT,
                            HANDLE_PREFIX,
                            PLATFORM
                        )
                    )
                )
            )
        );

        vm.prank(OWNER);
        registry.setZkVerifier(PLATFORM, IZkSessionVerifier(address(verifier)));
        vm.warp(1_000_000);
    }

    // ─── Builders ────────────────────────────────────────────────────

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _tokenSentRevealed() internal pure returns (bytes memory) {
        // `client_id=<X_CLIENT_ID>` somewhere in the body satisfies the matcher.
        return abi.encodePacked("grant_type=authorization_code&client_id=", X_CLIENT_ID, "&code=xyz");
    }

    /// Returns the prefix part of /me sentRevealed (ending with
    /// `authorization: Bearer `). The full sentRevealed under H1 is this
    /// prefix concatenated with the 2-byte `\r\n` CRLF trailer.
    function _meSentRevealedPrefix() internal view returns (bytes memory) {
        return abi.encodePacked("GET ", ENDPOINT, " HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer ");
    }

    function _meRecvRevealed(string memory handle) internal pure returns (bytes memory) {
        // Minimal JSON snippet with the handle quoted.
        return abi.encodePacked("{\"data\":{\"id\":\"42\",", HANDLE_PREFIX, handle, "\",\"name\":\"X\"}}");
    }

    function _buildTokenAttest(bytes32 bearerHash, uint64 ts)
        internal
        view
        returns (XZkVerifier.TokenAttestation memory att)
    {
        att.bearerHash = bearerHash;
        att.bearerRangeStart = 100;
        att.bearerRangeEnd = 200;
        att.sentRevealed = _tokenSentRevealed();
        att.timestamp = ts;
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(verifier),
                keccak256(bytes(PLATFORM)),
                keccak256("XZkVerifier.token.v1"),
                att.bearerHash,
                uint256(att.bearerRangeStart),
                uint256(att.bearerRangeEnd),
                keccak256(att.sentRevealed),
                uint256(att.timestamp)
            )
        );
        att.notarySignature = _sign(NOTARY_PK, digest);
    }

    function _buildMeAttest(bytes32 bearerHash, string memory handle, address sessionAddr, uint64 ts)
        internal
        view
        returns (XZkVerifier.MeAttestation memory att)
    {
        bytes memory prefix = _meSentRevealedPrefix();
        bytes memory recv = _meRecvRevealed(handle);
        att.bearerHash = bearerHash;
        att.bearerRangeStart = uint32(prefix.length);
        att.bearerRangeEnd = att.bearerRangeStart + 100;
        // sentRevealed = prefix bytes + CRLF (2 bytes) — H1 layout.
        att.sentRevealed = abi.encodePacked(prefix, bytes("\r\n"));
        att.sentPrefixEnd = uint32(prefix.length);
        att.sentSuffixEnd = att.bearerRangeEnd + 2;
        att.recvRevealed = recv;
        att.handle = handle;
        att.userId = "42"; // matches the "id":"42" snippet in _meRecvRevealed
        att.sessionAddr = sessionAddr;
        att.timestamp = ts;
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(verifier),
                keccak256(bytes(PLATFORM)),
                keccak256("XZkVerifier.me.v1"),
                att.bearerHash,
                uint256(att.bearerRangeStart),
                uint256(att.bearerRangeEnd),
                keccak256(att.sentRevealed),
                uint256(att.sentPrefixEnd),
                uint256(att.sentSuffixEnd),
                keccak256(att.recvRevealed),
                keccak256(bytes(att.handle)),
                keccak256(bytes(att.userId)),
                att.sessionAddr,
                uint256(att.timestamp)
            )
        );
        att.notarySignature = _sign(NOTARY_PK, digest);
    }

    /// Layout: bearer_hash_token[32] | bearer_hash_me[32] | nullifier[32]
    ///         | wallet[20] | session[20] = 136 slots, one byte per slot.
    function _buildPI(
        bytes32 bearerHashToken,
        bytes32 bearerHashMe,
        bytes32 nullifier,
        address wallet,
        address sessionAddr
    ) internal pure returns (bytes32[] memory pi) {
        pi = new bytes32[](136);
        for (uint256 i = 0; i < 32; i++) {
            pi[i] = bytes32(uint256(uint8(bearerHashToken[i])));
            pi[32 + i] = bytes32(uint256(uint8(bearerHashMe[i])));
            pi[64 + i] = bytes32(uint256(uint8(nullifier[i])));
        }
        bytes20 w = bytes20(wallet);
        bytes20 s = bytes20(sessionAddr);
        for (uint256 i = 0; i < 20; i++) {
            pi[96 + i] = bytes32(uint256(uint8(w[i])));
            pi[116 + i] = bytes32(uint256(uint8(s[i])));
        }
    }

    function _buildPayload(
        bytes32 bearerHash,
        bytes32 nullifier,
        address wallet,
        address sessionAddr,
        string memory handle
    ) internal view returns (bytes memory) {
        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, handle, sessionAddr, uint64(block.timestamp));
        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, wallet, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        return abi.encode(p);
    }

    // ─── Tests ───────────────────────────────────────────────────────

    function test_happyPath() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address wallet = address(0x1111);

        bytes memory payload = _buildPayload(bearerHash, nullifier, wallet, sessionAddr, "alice");

        vm.prank(wallet);
        (
            string memory handle,
            address sk,
            address piWallet,
            uint256 expiresAt,
            bytes32 returnedNullifier,
            string memory rUserId
        ) = verifier.verifyAndExtract(payload);

        assertEq(handle, "alice");
        assertEq(sk, sessionAddr);
        assertEq(piWallet, wallet);
        assertGt(expiresAt, block.timestamp);
        bytes32 expected = keccak256(abi.encode(keccak256(bytes(PLATFORM)), nullifier));
        assertEq(returnedNullifier, expected);
    }

    function test_walletAddress_returnedFromPi() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);

        // Verify across three distinct wallet PI values to catch a regression
        // where the verifier silently masks/truncates/replaces the returned
        // walletAddress. Registry consumes this exact value to enforce the
        // register-zero / link-msg.sender contract.
        address[3] memory wallets = [
            address(0),
            address(0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF),
            address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266) // Anvil acct 0
        ];
        for (uint256 i = 0; i < wallets.length; i++) {
            bytes memory payload = _buildPayload(bearerHash, nullifier, wallets[i], sessionAddr, "alice");
            (,, address piWallet,,,) = verifier.verifyAndExtract(payload);
            assertEq(piWallet, wallets[i]);
        }
    }

    function test_bearerHashMismatch_token_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest =
            _buildTokenAttest(bytes32(uint256(0xBADBEEF)), uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, "alice", sessionAddr, uint64(block.timestamp));
        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        bytes memory payload = abi.encode(p);

        vm.prank(w);
        vm.expectRevert(XZkVerifier.BearerHashMismatch.selector);
        verifier.verifyAndExtract(payload);
    }

    /// Symmetric: PI[bearer_hash_me] != meAttest.bearerHash must revert too.
    /// Catches the case where /token attestation matches but /me doesn't --
    /// the dual-blinder cross-bind enforces BOTH commits independently.
    function test_bearerHashMismatch_me_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bytes32(uint256(0xBADBEEF)), "alice", sessionAddr, uint64(block.timestamp));
        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        bytes memory payload = abi.encode(p);

        vm.prank(w);
        vm.expectRevert(XZkVerifier.BearerHashMismatch.selector);
        verifier.verifyAndExtract(payload);
    }

    /// PI[bearer_hash_token] and PI[bearer_hash_me] must each match THEIR
    /// own attestation; they can legitimately differ (two different
    /// blinders) but each must equal the corresponding notary commit.
    /// Tampering PI[token] alone while leaving attestations valid still
    /// reverts on the cross-bind check.
    function test_bearerHashMismatch_piTokenTampered_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, "alice", sessionAddr, uint64(block.timestamp));
        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bytes32(uint256(0xCAFEBABE)), bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        bytes memory payload = abi.encode(p);

        vm.prank(w);
        vm.expectRevert(XZkVerifier.BearerHashMismatch.selector);
        verifier.verifyAndExtract(payload);
    }

    function test_sessionAddrMismatch_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address piSession = address(0x5E5510);
        address attestSession = address(0xD1FFE2);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, "alice", attestSession, uint64(block.timestamp));
        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, piSession),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        bytes memory payload = abi.encode(p);

        vm.prank(w);
        vm.expectRevert(XZkVerifier.SessionAddrMismatch.selector);
        verifier.verifyAndExtract(payload);
    }

    function test_honkVerifierFalse_reverts() public {
        honk.setRet(false);
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        bytes memory payload = _buildPayload(bearerHash, nullifier, w, sessionAddr, "alice");
        vm.prank(w);
        vm.expectRevert(XZkVerifier.ZkVerificationFailed.selector);
        verifier.verifyAndExtract(payload);
    }

    function test_handleNotFound_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, "alice", sessionAddr, uint64(block.timestamp));
        // Replace recvRevealed with something missing the handle.
        meAttest.recvRevealed = bytes("{\"data\":{\"id\":\"42\"}}");
        // Re-sign with the tampered field.
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(verifier),
                keccak256(bytes(PLATFORM)),
                keccak256("XZkVerifier.me.v1"),
                meAttest.bearerHash,
                uint256(meAttest.bearerRangeStart),
                uint256(meAttest.bearerRangeEnd),
                keccak256(meAttest.sentRevealed),
                uint256(meAttest.sentPrefixEnd),
                uint256(meAttest.sentSuffixEnd),
                keccak256(meAttest.recvRevealed),
                keccak256(bytes(meAttest.handle)),
                meAttest.sessionAddr,
                uint256(meAttest.timestamp)
            )
        );
        meAttest.notarySignature = _sign(NOTARY_PK, digest);

        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        bytes memory payload = abi.encode(p);

        vm.prank(w);
        vm.expectRevert(XZkVerifier.HandleNotFound.selector);
        verifier.verifyAndExtract(payload);
    }

    function test_clientIdMismatch_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        // Replace sentRevealed with a body missing client_id.
        tokenAttest.sentRevealed = bytes("grant_type=authorization_code&code=xyz");
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
            _buildMeAttest(bearerHash, "alice", sessionAddr, uint64(block.timestamp));
        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        bytes memory payload = abi.encode(p);

        vm.prank(w);
        vm.expectRevert(XZkVerifier.ClientIdMismatch.selector);
        verifier.verifyAndExtract(payload);
    }

    function test_meRequestPrefix_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, "alice", sessionAddr, uint64(block.timestamp));
        // Tamper sentRevealed: wrong method, but still ends with CRLF after
        // the (would-be) bearer. Re-sign so digest matches.
        bytes memory badPrefix = bytes("POST /wrong HTTP/1.1\r\nauthorization: Bearer ");
        meAttest.sentRevealed = abi.encodePacked(badPrefix, bytes("\r\n"));
        meAttest.sentPrefixEnd = uint32(badPrefix.length);
        meAttest.bearerRangeStart = meAttest.sentPrefixEnd;
        meAttest.sentSuffixEnd = meAttest.bearerRangeEnd + 2;
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(verifier),
                keccak256(bytes(PLATFORM)),
                keccak256("XZkVerifier.me.v1"),
                meAttest.bearerHash,
                uint256(meAttest.bearerRangeStart),
                uint256(meAttest.bearerRangeEnd),
                keccak256(meAttest.sentRevealed),
                uint256(meAttest.sentPrefixEnd),
                uint256(meAttest.sentSuffixEnd),
                keccak256(meAttest.recvRevealed),
                keccak256(bytes(meAttest.handle)),
                meAttest.sessionAddr,
                uint256(meAttest.timestamp)
            )
        );
        meAttest.notarySignature = _sign(NOTARY_PK, digest);

        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });
        bytes memory payload = abi.encode(p);

        vm.prank(w);
        vm.expectRevert(XZkVerifier.MeRequestPrefixMismatch.selector);
        verifier.verifyAndExtract(payload);
    }

    /// H1 — bearer-end CRLF anchor (revert paths).
    ///
    /// Builds a happy-path me attestation, then for each of the three new H1
    /// guards: corrupts one field, re-signs the notary digest with the new
    /// field, asserts the contract reverts on the corresponding error.
    /// All three guards are independent of A0.1; they prevent prover-side
    /// bearer truncation by canonicalizing `bearer_len` via the trailing
    /// CRLF byte pair.

    /// H1: trailing 2 bytes of sentRevealed must equal `\r\n`.
    function test_meBearerEndNotCrlf_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, "alice", sessionAddr, uint64(block.timestamp));

        // Replace the trailing CRLF with garbage; preserve length so layout
        // and adjacency checks still pass — only `MeBearerEndNotCrlf` fires.
        bytes memory sent = meAttest.sentRevealed;
        sent[sent.length - 2] = 0x41; // 'A'
        sent[sent.length - 1] = 0x42; // 'B'
        meAttest.sentRevealed = sent;
        meAttest.notarySignature = _signMe(meAttest);

        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });

        vm.prank(w);
        vm.expectRevert(XZkVerifier.MeBearerEndNotCrlf.selector);
        verifier.verifyAndExtract(abi.encode(p));
    }

    /// H1: sentRevealed length must equal sentPrefixEnd + 2 (prefix bytes +
    /// 2-byte CRLF trailer). Anything else = bad multi-range layout.
    function test_meBadSentLayout_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, "alice", sessionAddr, uint64(block.timestamp));

        // Append a third byte so layout != prefixLen + 2.
        meAttest.sentRevealed = abi.encodePacked(meAttest.sentRevealed, bytes("X"));
        meAttest.notarySignature = _signMe(meAttest);

        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });

        vm.prank(w);
        vm.expectRevert(XZkVerifier.MeBadSentLayout.selector);
        verifier.verifyAndExtract(abi.encode(p));
    }

    /// H1: sentSuffixEnd MUST equal bearerRangeEnd + 2. Catches a prover
    /// claiming a 2-byte tail that does not abut the bearer (e.g. CRLF taken
    /// from a different line in the request).
    function test_meBearerEndAdjacencyMismatch_reverts() public {
        bytes32 bearerHash = bytes32(uint256(0xBEEF));
        bytes32 nullifier = bytes32(uint256(0xC0FFEE));
        address sessionAddr = address(0x5E5510);
        address w = address(0x1111);

        XZkVerifier.TokenAttestation memory tokenAttest = _buildTokenAttest(bearerHash, uint64(block.timestamp));
        XZkVerifier.MeAttestation memory meAttest =
            _buildMeAttest(bearerHash, "alice", sessionAddr, uint64(block.timestamp));

        // Shift sentSuffixEnd one byte off canonical adjacency.
        meAttest.sentSuffixEnd = meAttest.bearerRangeEnd + 3;
        meAttest.notarySignature = _signMe(meAttest);

        XZkVerifier.XProof memory p = XZkVerifier.XProof({
            proof: hex"",
            publicInputs: _buildPI(bearerHash, bearerHash, nullifier, w, sessionAddr),
            tokenAttest: tokenAttest,
            meAttest: meAttest
        });

        vm.prank(w);
        vm.expectRevert(XZkVerifier.MeBearerEndAdjacencyMismatch.selector);
        verifier.verifyAndExtract(abi.encode(p));
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    /// Re-sign a me-attestation digest after one of its fields was mutated.
    /// Mirrors `XZkVerifier._verifyMeSig` field order exactly.
    function _signMe(XZkVerifier.MeAttestation memory att) internal view returns (bytes memory) {
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(verifier),
                keccak256(bytes(PLATFORM)),
                keccak256("XZkVerifier.me.v1"),
                att.bearerHash,
                uint256(att.bearerRangeStart),
                uint256(att.bearerRangeEnd),
                keccak256(att.sentRevealed),
                uint256(att.sentPrefixEnd),
                uint256(att.sentSuffixEnd),
                keccak256(att.recvRevealed),
                keccak256(bytes(att.handle)),
                keccak256(bytes(att.userId)),
                att.sessionAddr,
                uint256(att.timestamp)
            )
        );
        return _sign(NOTARY_PK, digest);
    }
}
