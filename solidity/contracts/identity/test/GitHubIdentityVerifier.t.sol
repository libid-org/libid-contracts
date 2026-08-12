// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IdentityClaim} from "../IIdentityVerifier.sol";
import {GitHubIdentityVerifier} from "../GitHubIdentityVerifier.sol";
import {Notary} from "../../notary/Notary.sol";
import {deployNotary} from "../../notary/test/DeployNotary.sol";

/// The GitHub verifier reads the naming system's own notarized proof and
/// reports the account it names. It holds its own keys and its own response
/// shape, and the notary digest binds this contract, so nothing here stands
/// in for a wallet contract.
contract GitHubIdentityVerifierTest is Test {
    GitHubIdentityVerifier internal adapter;
    Notary internal notaryContract;

    uint256 internal constant NOTARY_PK = 0xA001;
    address internal notary;
    address internal owner = makeAddr("owner");
    address internal wallet = makeAddr("wallet");

    string internal constant DOMAIN = "api.github.com";
    string internal constant ENDPOINT = "/user";
    string internal constant HANDLE_PREFIX = "\"login\":\"";
    string internal constant ID_PREFIX = "\"id\":";
    string internal constant ID_SUFFIX = ",";

    function setUp() public {
        notary = vm.addr(NOTARY_PK);
        notaryContract = deployNotary(owner, notary);

        GitHubIdentityVerifier impl = new GitHubIdentityVerifier();
        adapter = GitHubIdentityVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    // GitHub's id is a bare number ending at a comma, where X
                    // quotes its own — the difference this shape is here to say.
                    abi.encodeCall(GitHubIdentityVerifier.initialize, (owner, address(notaryContract), _githubShape()))
                )
            )
        );

        vm.warp(1_000_000);
    }

    // ─── One proof, four leaves ─────────────────────────────────────

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _leaf(string memory prefix, bytes memory value) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encodePacked(prefix, value))));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    struct ProofArgs {
        string handle;
        string userId;
        address walletAddress;
        uint256 timestamp;
    }

    function _defaults() internal view returns (ProofArgs memory a) {
        a.handle = "octocat";
        a.userId = "583231";
        a.walletAddress = wallet;
        a.timestamp = block.timestamp;
    }

    /// One platform's response shape, as this contract stores it.
    struct PlatformStrings {
        string domain;
        string endpoint;
        string handlePrefix;
        string idPrefix;
        string idSuffix;
    }

    function _github() internal pure returns (PlatformStrings memory) {
        return PlatformStrings(DOMAIN, ENDPOINT, HANDLE_PREFIX, ID_PREFIX, ID_SUFFIX);
    }

    function _githubShape() internal pure returns (GitHubIdentityVerifier.ResponseShape memory) {
        return GitHubIdentityVerifier.ResponseShape(ENDPOINT, HANDLE_PREFIX, ID_PREFIX, ID_SUFFIX);
    }

    function _payload(ProofArgs memory a) internal view returns (bytes memory) {
        return _payloadFor(_github(), a);
    }

    /// Four leaves in a balanced tree: (domain, username) and (endpoint, id).
    ///
    /// Takes the platform rather than assuming GitHub, so a test can build a
    /// proof that is genuine for a DIFFERENT platform — notary signature,
    /// domain hash and every leaf consistent — and check that the adapter
    /// refuses it for being the wrong one, not for being malformed.
    function _payloadFor(PlatformStrings memory pf, ProofArgs memory a) internal view returns (bytes memory) {
        bytes32 lDomain = _leaf("domain:", bytes(pf.domain));
        bytes32 lUser = _leaf("recv:", abi.encodePacked(pf.handlePrefix, a.handle, '"'));
        bytes32 lEndpoint = _leaf("endpoint:", bytes(pf.endpoint));
        bytes32 lId = _leaf("recv:", abi.encodePacked(pf.idPrefix, a.userId, pf.idSuffix));

        bytes32 hDU = _hashPair(lDomain, lUser);
        bytes32 hEId = _hashPair(lEndpoint, lId);
        bytes32 root = _hashPair(hDU, hEId);

        GitHubIdentityVerifier.FullTlsProof memory t;
        t.walletAddress = a.walletAddress;
        t.domainHash = keccak256(bytes(pf.domain));
        t.clientRandom = keccak256("client");
        t.serverRandom = keccak256("server");
        t.serverEphemeralKey = bytes("ephemeral-key");
        t.transcriptRoot = root;
        t.timestamp = a.timestamp;

        t.domainPath = new bytes32[](2);
        t.domainPath[0] = lUser;
        t.domainPath[1] = hEId;

        t.usernamePath = new bytes32[](2);
        t.usernamePath[0] = lDomain;
        t.usernamePath[1] = hEId;

        t.endpointPath = new bytes32[](2);
        t.endpointPath[0] = lId;
        t.endpointPath[1] = hDU;

        t.idPath = new bytes32[](2);
        t.idPath[0] = lEndpoint;
        t.idPath[1] = hDU;

        t.notarySignature = _sign(
            NOTARY_PK,
            keccak256(
                abi.encode(
                    block.chainid,
                    address(adapter),
                    t.domainHash,
                    t.clientRandom,
                    t.serverRandom,
                    keccak256(t.serverEphemeralKey),
                    t.transcriptRoot,
                    t.timestamp
                )
            )
        );

        return abi.encode(
            GitHubIdentityVerifier.GitHubProof({
                tls: t, domain: pf.domain, handle: a.handle, userId: a.userId, endpoint: pf.endpoint
            })
        );
    }

    // ─── What it reads ──────────────────────────────────────────────

    function test_aLinkProofYieldsTheAccountItNames() public view {
        IdentityClaim memory claim = adapter.verify(_payload(_defaults()));

        assertEq(claim.handle, "octocat");
        assertEq(claim.userId, "583231");
        assertEq(claim.target, wallet);
        assertEq(claim.observedAt, uint64(block.timestamp));
    }

    /// A proof made out to nobody. `IdentityNames` refuses a claim naming
    /// nobody — anybody could redirect it — so the proof has to name the
    /// address that will hold the name.
    function test_aRegistrationProofNamesNobodyAndIsUnusable() public view {
        ProofArgs memory a = _defaults();
        a.walletAddress = address(0);

        IdentityClaim memory claim = adapter.verify(_payload(a));
        assertEq(claim.target, address(0), "a registration proof names no wallet");
    }

    // ─── What it refuses ────────────────────────────────────────────

    /// Two independent signatures have to agree. This platform is the strict
    /// one: forging a name needs both keys. The notary key now rotates on the
    /// shared Notary contract, and this consumer follows it.
    function test_aNotarySignatureFromAnotherKeyIsRefused() public {
        bytes memory payload = _payload(_defaults());
        vm.prank(owner);
        notaryContract.setNotary(makeAddr("someone else"));

        vm.expectRevert(GitHubIdentityVerifier.NotaryVerificationFailed.selector);
        adapter.verify(payload);
    }

    /// The handle is a Merkle leaf, so it cannot be swapped after signing.
    function test_aHandleTheTranscriptDoesNotCarryIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes memory payload = _payload(a);

        // Rebuild the claim around a different handle, keeping the signed root.
        GitHubIdentityVerifier.GitHubProof memory p = abi.decode(payload, (GitHubIdentityVerifier.GitHubProof));
        p.handle = "mallory";

        vm.expectRevert(GitHubIdentityVerifier.InvalidMerkleProof.selector);
        adapter.verify(abi.encode(p));
    }

    function test_anIdTheTranscriptDoesNotCarryIsRefused() public {
        bytes memory payload = _payload(_defaults());
        GitHubIdentityVerifier.GitHubProof memory p = abi.decode(payload, (GitHubIdentityVerifier.GitHubProof));
        p.userId = "999";

        vm.expectRevert(GitHubIdentityVerifier.InvalidMerkleProof.selector);
        adapter.verify(abi.encode(p));
    }

    /// Revealing the endpoint is what pins which API answered. A transcript
    /// from another endpoint must not pass as `/user`.
    function test_anEndpointThisContractDoesNotExpectIsRefused() public {
        bytes memory payload = _payload(_defaults());
        GitHubIdentityVerifier.GitHubProof memory p = abi.decode(payload, (GitHubIdentityVerifier.GitHubProof));
        p.endpoint = "/gists";

        vm.expectRevert(GitHubIdentityVerifier.WrongEndpoint.selector);
        adapter.verify(abi.encode(p));
    }

    /// The check that keeps this verifier GitHub's.
    ///
    /// The domain travels as a field because the notary signs its hash rather
    /// than the string, so the contract has to be told which string it is. That
    /// makes it honest about which platform answered and says nothing about
    /// whether that is the platform this contract speaks for.
    ///
    /// The proof built here is a genuine X one: X's response shape, X's leaves,
    /// a notary signature over X's domain hash, made out to this contract.
    /// Nothing about it is malformed. Without the pin it verifies, and
    /// `IdentityNames` — which keys on the platform id the CALLER passed, and
    /// registers this contract under GitHub's — writes an X account onto a
    /// GitHub name.
    function test_aProofForAnotherPlatformIsRefused() public {
        PlatformStrings memory x = PlatformStrings("api.x.com", "/2/users/me", "\"username\":\"", "\"id\":\"", "\"");
        vm.prank(owner);
        adapter.setResponseShape(
            GitHubIdentityVerifier.ResponseShape(x.endpoint, x.handlePrefix, x.idPrefix, x.idSuffix)
        );

        vm.expectRevert(abi.encodeWithSelector(GitHubIdentityVerifier.WrongPlatform.selector, x.domain));
        adapter.verify(_payloadFor(x, _defaults()));
    }

    /// An empty prefix matches at every position, so a leaf built from one
    /// proves nothing about where the value sits. Refused at configuration
    /// time, where it is still a mistake rather than a hole.
    function test_anEmptyResponseShapeIsRefused() public {
        vm.prank(owner);
        vm.expectRevert(GitHubIdentityVerifier.EmptyResponseShape.selector);
        adapter.setResponseShape(GitHubIdentityVerifier.ResponseShape(ENDPOINT, "", ID_PREFIX, ID_SUFFIX));
    }

    function test_aZeroSignerIsRefused() public {
        GitHubIdentityVerifier impl = new GitHubIdentityVerifier();
        vm.expectRevert(GitHubIdentityVerifier.ZeroSigner.selector);
        new ERC1967Proxy(
            address(impl), abi.encodeCall(GitHubIdentityVerifier.initialize, (owner, address(0), _githubShape()))
        );
    }

    function test_KNOWN_GAP_aProofCanBeRedirectedToAnotherWallet() public {
        ProofArgs memory a = _defaults();
        a.walletAddress = makeAddr("attacker");
        IdentityClaim memory claim = adapter.verify(_payload(a));
        assertEq(claim.target, makeAddr("attacker"), "re-pointed proof still verifies");
    }

    /// The adapter reads the notary through the shared Notary contract.
    function test_theNotaryIsReadThroughTheNotaryContract() public {
        assertEq(address(adapter.notaryContract()), address(notaryContract));
        assertEq(adapter.notary(), notary);
        vm.prank(owner);
        notaryContract.setNotary(makeAddr("rotated"));
        assertEq(adapter.notary(), makeAddr("rotated"));
    }

    function test_aStaleProofIsRefused() public {
        bytes memory payload = _payload(_defaults());

        vm.warp(block.timestamp + 61 minutes);
        vm.expectRevert(GitHubIdentityVerifier.StaleProof.selector);
        adapter.verify(payload);
    }

    function test_aProofFromTheFutureIsRefused() public {
        ProofArgs memory a = _defaults();
        a.timestamp = block.timestamp + 10 minutes;

        bytes memory payload = _payload(a);
        vm.expectRevert(GitHubIdentityVerifier.FutureProof.selector);
        adapter.verify(payload);
    }

    function test_anEmptyIdIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes memory payload = _payload(a);
        GitHubIdentityVerifier.GitHubProof memory p = abi.decode(payload, (GitHubIdentityVerifier.GitHubProof));
        p.userId = "";

        vm.expectRevert(GitHubIdentityVerifier.UserIdRequired.selector);
        adapter.verify(abi.encode(p));
    }
}
