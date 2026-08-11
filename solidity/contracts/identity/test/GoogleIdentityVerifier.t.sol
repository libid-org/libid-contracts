// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IdentityClaim} from "../IIdentityVerifier.sol";
import {GoogleIdentityVerifier} from "../GoogleIdentityVerifier.sol";

/// The root list, reduced to what the verifier asks it: whether a modulus is
/// trusted and until when. `IdentityJwksRoots` has its own tests for how an
/// entry gets there.
contract StubJwksRoots {
    mapping(bytes32 => uint256) public trustedHashExpiresAt;

    function trust(bytes32 modulusHash, uint256 until) external {
        trustedHashExpiresAt[modulusHash] = until;
    }
}

contract MockHonk {
    bool public ok = true;

    function setOk(bool v) external {
        ok = v;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return ok;
    }
}

/// The Google verifier reads a Google-signed id_token proof and reports the
/// account. The circuit commits the contract that will verify, and that is this
/// one — nothing here stands in for a wallet contract.
contract GoogleIdentityVerifierTest is Test {
    GoogleIdentityVerifier internal adapter;
    StubJwksRoots internal roots;
    MockHonk internal honk;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    string internal constant EMAIL = "alice@example.com";
    string internal constant SUB = "104729183746152938475";

    function setUp() public {
        honk = new MockHonk();
        roots = new StubJwksRoots();

        GoogleIdentityVerifier impl = new GoogleIdentityVerifier();
        adapter = GoogleIdentityVerifier(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(GoogleIdentityVerifier.initialize, (owner, address(honk), address(roots)))
                )
            )
        );

        vm.warp(1_000_000);
    }

    // ─── Building a proof the circuit would have produced ────────────

    struct ProofArgs {
        string email;
        string sub;
        address target;
        uint256 exp;
        uint256 chainId;
        address verifierAddr;
        bytes32 audHigh;
        bytes32 audLow;
    }

    function _defaults() internal view returns (ProofArgs memory a) {
        a.email = EMAIL;
        a.sub = SUB;
        a.target = alice;
        a.exp = block.timestamp + 1 hours;
        a.chainId = block.chainid;
        a.verifierAddr = address(adapter);
        // The audience halves are whatever the token carried. The adapter does
        // not read them, which is the point of the platform.
        a.audHigh = bytes32(uint256(0xAAAA));
        a.audLow = bytes32(uint256(0xBBBB));
    }

    function _publicInputs(ProofArgs memory a) internal pure returns (bytes32[] memory pi) {
        pi = new bytes32[](28);
        // Modulus limbs [0..18) — any value, as long as the root list
        // trusts its hash.
        for (uint256 i = 0; i < 18; i++) {
            pi[i] = bytes32(uint256(i + 1));
        }
        (bytes32 e0, bytes32 e1) = _pack62(_padTo62(bytes(a.email)));
        pi[18] = e0;
        pi[19] = e1;
        (bytes32 n0, bytes32 n1) = _pack62(_padTo62(_addressToAscii(a.target)));
        pi[20] = n0;
        pi[21] = n1;
        pi[22] = _pack31(_padTo31(bytes(a.sub)));
        pi[23] = bytes32(a.exp);
        pi[24] = a.audHigh;
        pi[25] = a.audLow;
        pi[26] = bytes32(a.chainId);
        pi[27] = bytes32(uint256(uint160(a.verifierAddr)));
    }

    /// Build the proof and make its modulus trusted, the way a rotation would.
    function _payload(ProofArgs memory a) internal returns (bytes memory) {
        bytes32[] memory pi = _publicInputs(a);
        bytes memory packed = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; i++) {
            bytes32 v = pi[i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), v)
            }
        }
        roots.trust(keccak256(packed), block.timestamp + 30 days);

        return abi.encode(
            GoogleIdentityVerifier.UserProof({
                honkProof: hex"00", publicInputs: pi, email: a.email, sessionKey: a.target, sub: a.sub
            })
        );
    }

    // ─── What it reads ──────────────────────────────────────────────

    function test_aProofYieldsTheAccountItNames() public {
        IdentityClaim memory claim = adapter.verify(_payload(_defaults()));

        assertEq(claim.handle, EMAIL);
        assertEq(claim.userId, SUB);
        assertEq(claim.target, alice);
        assertEq(claim.observedAt, uint64(block.timestamp + 1 hours));
    }

    /// The decision this adapter exists to make. A token minted for another
    /// Google application still proves the account: the sub, the email and the
    /// wallet in the nonce are all Google-signed.
    function test_aTokenForAnotherGoogleAppIsAccepted() public {
        ProofArgs memory a = _defaults();
        a.audHigh = bytes32(uint256(0xDEAD));
        a.audLow = bytes32(uint256(0xBEEF));

        IdentityClaim memory claim = adapter.verify(_payload(a));
        assertEq(claim.userId, SUB);
    }

    /// The observation is the token's `exp`, which sits ahead of now. This is
    /// why the naming contract takes a per-platform allowance rather than
    /// refusing everything dated in the future.
    function test_theObservationIsAheadOfTheChain() public {
        IdentityClaim memory claim = adapter.verify(_payload(_defaults()));
        assertGt(claim.observedAt, uint64(block.timestamp));
    }

    // ─── What it still refuses ──────────────────────────────────────

    /// The circuit commits the contract that will verify. Without the check, a
    /// token minted for another deployment — including the wallet product's —
    /// would replay here.
    function test_aProofMintedForAnotherDeploymentIsRefused() public {
        ProofArgs memory a = _defaults();
        a.verifierAddr = makeAddr("another deployment");

        bytes memory payload = _payload(a);
        vm.expectRevert(GoogleIdentityVerifier.WrongVerifier.selector);
        adapter.verify(payload);
    }

    function test_aProofForAnotherChainIsRefused() public {
        ProofArgs memory a = _defaults();
        a.chainId = block.chainid + 1;

        bytes memory payload = _payload(a);
        vm.expectRevert(GoogleIdentityVerifier.WrongChain.selector);
        adapter.verify(payload);
    }

    /// Google rotates its signing keys, and the root list carries an expiry per
    /// modulus. Once it lapses the proof is refused, whatever else is true of
    /// it.
    function test_anUntrustedModulusIsRefused() public {
        bytes memory payload = _payload(_defaults());

        vm.warp(block.timestamp + 31 days);
        vm.expectRevert(GoogleIdentityVerifier.UntrustedModulus.selector);
        adapter.verify(payload);
    }

    function test_anExpiredTokenIsRefused() public {
        ProofArgs memory a = _defaults();
        a.exp = block.timestamp - 10 minutes;

        bytes memory payload = _payload(a);
        vm.expectRevert(GoogleIdentityVerifier.JwtExpired.selector);
        adapter.verify(payload);
    }

    /// The email is returned verbatim, so it has to be the one the circuit
    /// packed — otherwise the handle would be the caller's to choose.
    function test_anEmailTheProofDoesNotCarryIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes32[] memory pi = _publicInputs(a);
        bytes memory packed = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; i++) {
            bytes32 v = pi[i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), v)
            }
        }
        roots.trust(keccak256(packed), block.timestamp + 30 days);

        bytes memory payload = abi.encode(
            GoogleIdentityVerifier.UserProof({
                honkProof: hex"00", publicInputs: pi, email: "mallory@example.com", sessionKey: a.target, sub: a.sub
            })
        );

        vm.expectRevert(GoogleIdentityVerifier.WrongEmail.selector);
        adapter.verify(payload);
    }

    /// Same for the target: the wallet is inside the Google-signed nonce, so a
    /// claim naming a different one does not match the proof.
    function test_aTargetTheProofDoesNotCarryIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes32[] memory pi = _publicInputs(a);
        bytes memory packed = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; i++) {
            bytes32 v = pi[i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), v)
            }
        }
        roots.trust(keccak256(packed), block.timestamp + 30 days);

        bytes memory payload = abi.encode(
            GoogleIdentityVerifier.UserProof({
                honkProof: hex"00", publicInputs: pi, email: a.email, sessionKey: makeAddr("mallory"), sub: a.sub
            })
        );

        vm.expectRevert(GoogleIdentityVerifier.WrongAddress.selector);
        adapter.verify(payload);
    }

    function test_aFailingHonkProofIsRefused() public {
        bytes memory payload = _payload(_defaults());
        honk.setOk(false);

        vm.expectRevert(GoogleIdentityVerifier.BadHonkProof.selector);
        adapter.verify(payload);
    }

    // ─── The packed form names one input ────────────────────────────

    /// The circuit zero-pads, so `"123"` and `"123\0"` pack to the same field
    /// element. Without a NUL check the second reads as a valid proof of an
    /// account id Google never issued, and the binding lands on a node no
    /// reader can name — every reader asks for the id Google did issue.
    function test_anAccountIdPaddedWithNulIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes memory payload = _payloadStating(a, a.email, string(abi.encodePacked(SUB, hex"00")), a.target);

        vm.expectRevert(GoogleIdentityVerifier.EmbeddedNul.selector);
        adapter.verify(payload);
    }

    /// The same for the email, which is the handle a name resolves to.
    function test_anEmailPaddedWithNulIsRefused() public {
        ProofArgs memory a = _defaults();
        bytes memory payload = _payloadStating(a, string(abi.encodePacked(EMAIL, hex"00")), a.sub, a.target);

        vm.expectRevert(GoogleIdentityVerifier.EmbeddedNul.selector);
        adapter.verify(payload);
    }

    /// A Google Workspace address on a long custom domain does not fit the
    /// circuit and never will. It has to say so in an error a frontend can
    /// decode, rather than in a string matching nothing this contract declares.
    function test_anEmailTooLongForTheCircuitSaysSo() public {
        string memory long = "firstname.lastname.department@engineering.example-corporation.com";
        assertGt(bytes(long).length, 62, "the fixture has to exceed the cap");

        ProofArgs memory a = _defaults();
        bytes memory payload = _payloadStating(a, long, a.sub, a.target);

        vm.expectRevert(
            abi.encodeWithSelector(GoogleIdentityVerifier.TooLongForCircuit.selector, bytes(long).length, uint256(62))
        );
        adapter.verify(payload);
    }

    /// Build the proof for `a`, then encode it stating different plaintext. The
    /// public inputs stay what the circuit produced, which is the position a
    /// caller editing the payload is in.
    ///
    /// It trusts the modulus on the way, which is an external call — so a
    /// caller expecting a revert has to build the payload BEFORE arming
    /// `expectRevert`, or the cheatcode lands on that call instead.
    function _payloadStating(ProofArgs memory a, string memory email, string memory sub, address target)
        internal
        returns (bytes memory)
    {
        bytes32[] memory pi = _publicInputs(a);
        bytes memory packed = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; i++) {
            bytes32 v = pi[i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), v)
            }
        }
        roots.trust(keccak256(packed), block.timestamp + 30 days);

        return abi.encode(
            GoogleIdentityVerifier.UserProof({
                honkProof: hex"00", publicInputs: pi, email: email, sessionKey: target, sub: sub
            })
        );
    }

    // ─── Packing, mirroring the contract ────────────────────────────

    function _padTo62(bytes memory s) internal pure returns (bytes memory out) {
        out = new bytes(62);
        for (uint256 i = 0; i < s.length; i++) {
            out[i] = s[i];
        }
    }

    function _pack62(bytes memory p) internal pure returns (bytes32 hi, bytes32 lo) {
        uint256 h;
        uint256 l;
        for (uint256 i = 0; i < 31; i++) {
            h = h * 256 + uint8(p[i]);
            l = l * 256 + uint8(p[i + 31]);
        }
        hi = bytes32(h);
        lo = bytes32(l);
    }

    function _padTo31(bytes memory s) internal pure returns (bytes memory out) {
        out = new bytes(31);
        for (uint256 i = 0; i < s.length; i++) {
            out[i] = s[i];
        }
    }

    function _pack31(bytes memory p) internal pure returns (bytes32 packed) {
        uint256 v;
        for (uint256 i = 0; i < 31; i++) {
            v = v * 256 + uint8(p[i]);
        }
        packed = bytes32(v);
    }

    function _addressToAscii(address a) internal pure returns (bytes memory) {
        bytes memory out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        bytes16 hexc = "0123456789abcdef";
        uint160 v = uint160(a);
        for (uint256 i = 0; i < 20; i++) {
            uint8 b = uint8(v >> ((19 - i) * 8));
            out[2 + i * 2] = hexc[b >> 4];
            out[2 + i * 2 + 1] = hexc[b & 0x0f];
        }
        return out;
    }
}
