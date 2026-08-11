// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {GitHubIdentityVerifier} from "../GitHubIdentityVerifier.sol";
import {GoogleIdentityVerifier} from "../GoogleIdentityVerifier.sol";
import {XIdentityVerifier} from "../XIdentityVerifier.sol";

/// The browser builds a proof; a verifier decodes it. Nothing in the compiler
/// ties those two together — the browser writes the layout out by hand — so a
/// field added, moved or retyped on either side is a revert at binding time
/// with nothing to point at.
///
/// This is what points at it. The fixture holds the bytes the browser package
/// produced for a known proof, and each test decodes them here and reads the
/// values back out. Two languages agreeing with each other would only prove
/// they drift together; agreeing with one committed artefact is what catches
/// the drift.
///
/// The same file is asserted from the other side in `bind.test.ts`.
contract BindEncodingTest is Test {
    /// Shared parity fixture. Source of truth is the TS encoder in
    /// `ts/packages/contracts/src/identity/bind.ts`, which generates these
    /// bytes for a known proof; both the TS tests and this Solidity test
    /// assert against this one file. Regenerate with
    /// `pnpm -C ts/packages/contracts regen:fixtures`.
    string internal constant FIXTURE = "contracts/identity/test/fixtures/bind-encoding.json";

    address internal constant WALLET = 0x2222222222222222222222222222222222222222;
    address internal constant SESSION = 0x3333333333333333333333333333333333333333;

    function _b32(uint256 n) internal pure returns (bytes32) {
        return bytes32(n);
    }

    function test_theBrowsersGitHubProofDecodesHere() public view {
        bytes memory encoded = vm.parseJsonBytes(vm.readFile(FIXTURE), ".github");
        GitHubIdentityVerifier.GitHubProof memory p = abi.decode(encoded, (GitHubIdentityVerifier.GitHubProof));

        assertEq(p.domain, "api.github.com", "domain");
        assertEq(p.handle, "octocat", "handle");
        assertEq(p.userId, "583231", "user id");
        assertEq(p.endpoint, "/user", "endpoint");

        assertEq(p.tls.notarySignature, hex"aabb", "notary signature");
        assertEq(p.tls.backendSignature, hex"ccdd", "backend signature");
        assertEq(p.tls.userAddress, SESSION, "user address");
        assertEq(p.tls.walletAddress, WALLET, "wallet address");
        assertEq(p.tls.domainHash, _b32(1), "domain hash");
        assertEq(p.tls.clientRandom, _b32(2), "client random");
        assertEq(p.tls.serverRandom, _b32(3), "server random");
        assertEq(p.tls.serverEphemeralKey, hex"eeff", "ephemeral key");
        assertEq(p.tls.transcriptRoot, _b32(4), "transcript root");
        assertEq(p.tls.timestamp, 1_700_000_000, "timestamp");

        // The paths differ in length on purpose: a decoder that read them by
        // position rather than by offset would pass a uniform fixture.
        assertEq(p.tls.domainPath.length, 2, "domain path");
        assertEq(p.tls.domainPath[1], _b32(6), "domain path tail");
        assertEq(p.tls.usernamePath.length, 1, "username path");
        assertEq(p.tls.endpointPath.length, 0, "endpoint path");
        assertEq(p.tls.idPath.length, 3, "id path");
        assertEq(p.tls.idPath[2], _b32(10), "id path tail");
    }

    function test_theBrowsersXProofDecodesHere() public view {
        bytes memory encoded = vm.parseJsonBytes(vm.readFile(FIXTURE), ".x");
        XIdentityVerifier.XProof memory p = abi.decode(encoded, (XIdentityVerifier.XProof));

        assertEq(p.proof, hex"1234", "zk proof");
        assertEq(p.publicInputs.length, 2, "public inputs");
        assertEq(p.publicInputs[1], _b32(12), "public input tail");

        assertEq(p.meAttest.bearerHash, _b32(13), "bearer hash");
        assertEq(p.meAttest.bearerRangeStart, 100, "bearer start");
        assertEq(p.meAttest.bearerRangeEnd, 200, "bearer end");
        assertEq(p.meAttest.sentRevealed, hex"5566", "sent revealed");
        assertEq(p.meAttest.sentPrefixEnd, 100, "sent prefix end");
        assertEq(p.meAttest.sentSuffixEnd, 202, "sent suffix end");
        assertEq(p.meAttest.recvRevealed, hex"7788", "recv revealed");
        assertEq(p.meAttest.handle, "alice", "handle");
        assertEq(p.meAttest.userId, "42", "user id");
        assertEq(p.meAttest.sessionAddr, SESSION, "session address");
        assertEq(p.meAttest.timestamp, 1_700_000_001, "timestamp");
        assertEq(p.meAttest.notarySignature, hex"99aa", "notary signature");
    }

    function test_theBrowsersGoogleProofDecodesHere() public view {
        bytes memory encoded = vm.parseJsonBytes(vm.readFile(FIXTURE), ".google");
        GoogleIdentityVerifier.UserProof memory p = abi.decode(encoded, (GoogleIdentityVerifier.UserProof));

        assertEq(p.honkProof, hex"bbcc", "honk proof");
        assertEq(p.publicInputs.length, 3, "public inputs");
        assertEq(p.publicInputs[2], _b32(16), "public input tail");
        assertEq(p.email, "alice@example.com", "email");
        assertEq(p.sessionKey, WALLET, "target");
        assertEq(p.sub, "1234567890", "sub");
    }
}
