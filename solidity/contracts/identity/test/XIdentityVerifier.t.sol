// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IdentityClaim} from "../IIdentityVerifier.sol";
import {XIdentityVerifier} from "../XIdentityVerifier.sol";
import {Notary} from "../../notary/Notary.sol";
import {deployNotary} from "../../notary/test/DeployNotary.sol";

///
/// Only the getters matter: the adapter never calls the real one to verify
/// anything, it only asks it what the notary key and the response shape are.
/// Deploying the real one here would drag the wallet system into the identity
/// tree, which is the thing that has to stay extractable.
contract MockHonkVerifier {
    bool public ok = true;

    function setOk(bool v) external {
        ok = v;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return ok;
    }
}

/// The X verifier reads the naming system's own notarized proof and reports the
/// account it names. Both attestation digests bind this contract, so nothing
/// here stands in for a wallet contract.
contract XIdentityVerifierTest is Test {
    XIdentityVerifier internal adapter;
    MockHonkVerifier internal honk;
    Notary internal notaryContract;

    uint256 internal constant NOTARY_PK = 0xA001;
    address internal notary;
    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    string internal constant PLATFORM = "api.x.com";
    string internal constant ENDPOINT = "/2/users/me";
    string internal constant HANDLE_PREFIX = "\"username\":\"";
    string internal constant ID_PREFIX = "\"id\":\"";
    string internal constant ID_SUFFIX = "\"";

    function setUp() public {
        notary = vm.addr(NOTARY_PK);
        notaryContract = deployNotary(owner, notary);
        honk = new MockHonkVerifier();

        XIdentityVerifier impl = new XIdentityVerifier();
        adapter = XIdentityVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        XIdentityVerifier.initialize,
                        (
                            owner,
                            address(notaryContract),
                            address(honk),
                            XIdentityVerifier.ResponseShape(PLATFORM, ENDPOINT, HANDLE_PREFIX, ID_PREFIX, ID_SUFFIX)
                        )
                    )
                )
            )
        );

        vm.warp(1_000_000);
    }

    // ─── The proof, built the way the notary builds it ──────────────
    //
    // The digests below name the verifier itself. The naming system's notary is
    // told which contract it is attesting to, so a signature made out to
    // anything else does not recover here.

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NOTARY_PK, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _meSentPrefix() internal pure returns (bytes memory) {
        return abi.encodePacked("GET ", ENDPOINT, " HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer ");
    }

    function _meRecvRevealed(string memory handle, string memory userId) internal pure returns (bytes memory) {
        return abi.encodePacked("{\"data\":{\"id\":\"", userId, "\",", HANDLE_PREFIX, handle, "\",\"name\":\"X\"}}");
    }

    function _meAttest(bytes32 bearerHash, string memory handle, string memory userId, address sessionAddr, uint64 ts)
        internal
        view
        returns (XIdentityVerifier.MeAttestation memory att)
    {
        return _meAttest(bearerHash, handle, userId, sessionAddr, ts, _meRecvRevealed(handle, userId));
    }

    /// The same, stating a response written some other way. X may change how
    /// `/2/users/me` reads, and the shape is configuration for that reason.
    function _meAttest(
        bytes32 bearerHash,
        string memory handle,
        string memory userId,
        address sessionAddr,
        uint64 ts,
        bytes memory recvRevealed
    ) internal view returns (XIdentityVerifier.MeAttestation memory att) {
        bytes memory prefix = _meSentPrefix();
        att.bearerHash = bearerHash;
        att.bearerRangeStart = uint32(prefix.length);
        att.bearerRangeEnd = att.bearerRangeStart + 100;
        att.sentRevealed = abi.encodePacked(prefix, bytes("\r\n"));
        att.sentPrefixEnd = uint32(prefix.length);
        att.sentSuffixEnd = att.bearerRangeEnd + 2;
        att.recvRevealed = recvRevealed;
        att.handle = handle;
        att.userId = userId;
        att.sessionAddr = sessionAddr;
        att.timestamp = ts;
        att.notarySignature = _sign(
            keccak256(
                abi.encode(
                    block.chainid,
                    address(adapter),
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
            )
        );
    }

    /// Re-sign an attestation a test has edited. The notary signs the fields,
    /// so editing one without this only proves the signature check works.
    function _resign(XIdentityVerifier.MeAttestation memory att) internal view {
        att.notarySignature = _sign(
            keccak256(
                abi.encode(
                    block.chainid,
                    address(adapter),
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
            )
        );
    }

    function _publicInputs(bytes32 bearerHashToken, bytes32 bearerHashMe, address wallet, address sessionAddr)
        internal
        pure
        returns (bytes32[] memory pi)
    {
        pi = new bytes32[](136);
        for (uint256 i = 0; i < 32; i++) {
            pi[i] = bytes32(uint256(uint8(bearerHashToken[i])));
            pi[32 + i] = bytes32(uint256(uint8(bearerHashMe[i])));
        }
        bytes20 w = bytes20(wallet);
        bytes20 s = bytes20(sessionAddr);
        for (uint256 i = 0; i < 20; i++) {
            pi[96 + i] = bytes32(uint256(uint8(w[i])));
            pi[116 + i] = bytes32(uint256(uint8(s[i])));
        }
    }

    struct ProofArgs {
        string handle;
        string userId;
        address wallet;
        address sessionAddr;
        uint64 meTs;
    }

    function _defaults() internal returns (ProofArgs memory a) {
        a.handle = "alice";
        a.userId = "42";
        a.wallet = alice;
        a.sessionAddr = makeAddr("session");
        a.meTs = uint64(block.timestamp);
    }

    function _payload(ProofArgs memory a) internal view returns (bytes memory) {
        bytes32 bearerHash = keccak256("bearer");
        return abi.encode(
            XIdentityVerifier.XProof({
                proof: hex"00",
                publicInputs: _publicInputs(bearerHash, bearerHash, a.wallet, a.sessionAddr),
                meAttest: _meAttest(bearerHash, a.handle, a.userId, a.sessionAddr, a.meTs)
            })
        );
    }

    function _payloadAround(ProofArgs memory a, XIdentityVerifier.MeAttestation memory att)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(
            XIdentityVerifier.XProof({
                proof: hex"00",
                publicInputs: _publicInputs(att.bearerHash, att.bearerHash, a.wallet, a.sessionAddr),
                meAttest: att
            })
        );
    }

    // ─── What it reads ──────────────────────────────────────────────

    function test_aProofYieldsTheAccountItNames() public {
        IdentityClaim memory claim = adapter.verify(_payload(_defaults()));

        assertEq(claim.handle, "alice");
        assertEq(claim.userId, "42");
        assertEq(claim.target, alice);
        assertEq(claim.observedAt, uint64(block.timestamp));
    }

    /// The observation is when the notary saw the response, which is the only
    /// moment the claim describes. `IdentityNames` orders two proofs of one
    /// handle by it, so it must come from the notary and not the caller.
    function test_theObservationIsWhenTheResponseWasSeen() public {
        ProofArgs memory a = _defaults();
        a.meTs = uint64(block.timestamp) - 60;

        IdentityClaim memory claim = adapter.verify(_payload(a));
        assertEq(claim.observedAt, uint64(block.timestamp) - 60);
    }

    // ─── What it still refuses ──────────────────────────────────────

    /// The digest names this contract, so a signature by anybody else
    /// fails — including one made for this contract's own address.
    function test_aSignatureFromAnotherKeyIsRefused() public {
        bytes memory payload = _payload(_defaults());
        vm.prank(owner);
        notaryContract.setNotary(makeAddr("someone else"));

        vm.expectRevert(XIdentityVerifier.NotaryVerificationFailed.selector);
        adapter.verify(payload);
    }

    function test_aHandleTheResponseDoesNotCarryIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes32 bearerHash = keccak256("bearer");
        XIdentityVerifier.MeAttestation memory me = _meAttest(bearerHash, a.handle, a.userId, a.sessionAddr, a.meTs);
        me.handle = "mallory";

        bytes memory payload = abi.encode(
            XIdentityVerifier.XProof({
                proof: hex"00",
                publicInputs: _publicInputs(bearerHash, bearerHash, a.wallet, a.sessionAddr),
                meAttest: me
            })
        );

        vm.expectRevert(XIdentityVerifier.HandleNotFound.selector);
        adapter.verify(payload);
    }

    function test_aFailingZkProofIsRefused() public {
        bytes memory payload = _payload(_defaults());
        honk.setOk(false);

        vm.expectRevert(XIdentityVerifier.ZkVerificationFailed.selector);
        adapter.verify(payload);
    }

    function test_aStaleProofIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes memory payload = _payload(a);

        vm.warp(block.timestamp + 11 minutes);
        vm.expectRevert(XIdentityVerifier.StaleProof.selector);
        adapter.verify(payload);
    }

    /// The public input the circuit committed to has to agree with the value
    /// the notary signed. A name binding installs no session, but leaving the
    /// field unchecked would leave one part of the proof unverified.
    function test_aSessionAddressDisagreeingWithTheAttestationIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes32 bearerHash = keccak256("bearer");

        bytes memory payload = abi.encode(
            XIdentityVerifier.XProof({
                proof: hex"00",
                // Public inputs name a different session than the attestation.
                publicInputs: _publicInputs(bearerHash, bearerHash, a.wallet, makeAddr("elsewhere")),
                meAttest: _meAttest(bearerHash, a.handle, a.userId, a.sessionAddr, a.meTs)
            })
        );

        vm.expectRevert(XIdentityVerifier.SessionAddrMismatch.selector);
        adapter.verify(payload);
    }

    /// The bearer range is the caller's to state, and the end-adjacency check
    /// adds two to it. At the top of uint32 that sum overflows before any
    /// signature is read, so the caller gets an arithmetic panic instead of the
    /// error naming what is wrong — in a contract that does no user-facing
    /// arithmetic, and with nothing a frontend can decode.
    function test_aBearerRangeEndAtTheTopOfUint32IsRefusedRatherThanPanicking() public {
        ProofArgs memory a = _defaults();
        XIdentityVerifier.MeAttestation memory att =
            _meAttest(keccak256("bearer"), a.handle, a.userId, a.sessionAddr, a.meTs);
        att.bearerRangeEnd = type(uint32).max;
        _resign(att);

        bytes memory payload = _payloadAround(a, att);
        vm.expectRevert(XIdentityVerifier.MeBearerEndAdjacencyMismatch.selector);
        adapter.verify(payload);
    }

    /// The notary rotates on the shared Notary contract, for every consumer
    /// at once; this adapter follows the pointer.
    function test_theNotaryCanBeRotated() public {
        vm.prank(owner);
        notaryContract.setNotary(makeAddr("rotated"));

        assertEq(adapter.notary(), makeAddr("rotated"));
        assertEq(address(adapter.notaryContract()), address(notaryContract));
        assertEq(adapter.platformName(), "api.x.com");
    }

    /// An empty prefix matches at every position, and an empty platform name
    /// would leave the digest unpinned. Refused at configuration time.
    function test_anEmptyResponseShapeIsRefused() public {
        vm.prank(owner);
        vm.expectRevert(XIdentityVerifier.EmptyResponseShape.selector);
        adapter.setResponseShape(XIdentityVerifier.ResponseShape(PLATFORM, ENDPOINT, "", ID_PREFIX, ID_SUFFIX));
    }

    function test_anEmptyIdPrefixIsRefused() public {
        vm.prank(owner);
        vm.expectRevert(XIdentityVerifier.EmptyResponseShape.selector);
        adapter.setResponseShape(XIdentityVerifier.ResponseShape(PLATFORM, ENDPOINT, HANDLE_PREFIX, "", ID_SUFFIX));
    }

    /// The event `setResponseShape` exists for: X changes how `/2/users/me`
    /// writes the account id — here, a space after the colon. With the id
    /// delimiters hardcoded the owner could follow the handle and not the id,
    /// so every X bind would revert `IdNotFound` until an upgrade shipped.
    function test_theOwnerCanFollowAChangeInTheIdFormat() public {
        ProofArgs memory a = _defaults();
        bytes memory recv = abi.encodePacked("{\"data\":{\"id\": \"", a.userId, "\",", HANDLE_PREFIX, a.handle, "\"}}");
        bytes memory payload =
            _payloadAround(a, _meAttest(keccak256("bearer"), a.handle, a.userId, a.sessionAddr, a.meTs, recv));

        vm.expectRevert(XIdentityVerifier.IdNotFound.selector);
        adapter.verify(payload);

        vm.prank(owner);
        adapter.setResponseShape(
            XIdentityVerifier.ResponseShape(PLATFORM, ENDPOINT, HANDLE_PREFIX, "\"id\": \"", ID_SUFFIX)
        );

        IdentityClaim memory claim = adapter.verify(payload);
        assertEq(claim.userId, a.userId, "the same response now reads");
    }

    function test_aZeroTrustAddressIsRefused() public {
        vm.prank(owner);
        vm.expectRevert(XIdentityVerifier.ZeroSigner.selector);
        adapter.setHonkVerifier(address(0));
    }
}
