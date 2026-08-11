// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {IdentityClaim, IIdentityVerifier} from "./IIdentityVerifier.sol";

interface IHonkVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

/// Where the naming system keeps the Google keys it trusts. Its own contract,
/// in this same tree — see `IdentityJwksRoots`.
interface IJwksRoots {
    function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);
}

/// @title GoogleIdentityVerifier - the naming system's own Google proof.
///
/// @notice Verifies a zero-knowledge proof over a Google-signed id_token and
///         returns the account it names.
///
/// @dev **This contract is the one the token is minted for.** The circuit
///      commits the chain and the contract that will verify, and that
///      commitment is checked against `address(this)` — so a token minted for
///      anything else, including the wallet product, does not verify here. It
///      reads nothing from that product and shares no contract with it.
///
///      That is a duplicate of the wallet product's pipeline, on purpose. The
///      two speak the same protocol to the same issuer today and will drift
///      apart; a duplicate costs a second trust list, a shared one costs the
///      independence the naming system is for.
///
///      **What it trusts.** Its own Honk verifier address, and its own JWKS
///      root list — Google rotates its signing keys, and `IdentityJwksRoots`
///      is where this system learns the current ones. The rotation proof names
///      no contract, so the same notarized reading of Google's JWKS feeds both
///      lists without tying them together.
///
///      **What it does not check, and what that costs.** The `aud` claim — the
///      OAuth application the token was issued to. Any Google-signed id_token
///      verifies here, whoever minted it.
///
///      The naming argument for that: a token from another application still
///      proves the account, because the `sub` and the email are Google's and
///      the address the token names is inside the Google-signed `nonce`. So a
///      product built on these names does not have to be ours, and does not
///      have to ask us to be listed.
///
///      The price, stated plainly. Mallory registers her own Google OAuth
///      application and puts a "Sign in with Google" button on a site of her
///      own, with `nonce` set to her own wallet address. A victim clicks it
///      once. Mallory now holds a Google-signed token whose `sub` and email are
///      the victim's and whose nonce is Mallory's address. She builds the proof
///      herself — no notary, no TLS session, nobody's cooperation — and binds:
///      `target == msg.sender` holds, the account is genuine, the token is
///      fresh, the key is trusted. `resolveHandle` for the victim's address now
///      returns Mallory's wallet, and a payment sent to that name is hers.
///
///      The remedy is the real owner proving again, which needs them to notice
///      and does not recover what was already routed. It rests on one
///      invariant: `observedAt` is the token's `exp`, which Google sets, so a
///      later honest proof always outranks an earlier hostile one and
///      `IdentityNames` refuses an observation dated further ahead than the
///      platform allows. The remedy cannot be taken away, but it is a remedy
///      and not a defence. Read a Google name as "somebody proved this
///      account", not "the account holder chose this address".
contract GoogleIdentityVerifier is IIdentityVerifier, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// One proof over a Google-signed id_token.
    struct UserProof {
        bytes honkProof;
        bytes32[] publicInputs;
        string email;
        address sessionKey;
        /// Immutable Google account id (JWT `sub`). Identity binds on this.
        string sub;
    }

    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    uint256 public constant TOTAL_PUBLIC_INPUTS = 28;

    /// @notice The circuit's on-chain verifier.
    IHonkVerifier public honkVerifier;

    /// @notice The Google keys this system trusts, and until when.
    IJwksRoots public jwksRoots;

    error ZeroAddress();
    error WrongPublicInputCount();
    error BadHonkProof();
    error UntrustedModulus();
    error JwtExpired();
    /// The token's `exp` does not fit the claim's `observedAt`.
    error ExpiryOutOfRange(uint256 jwtExp);
    error WrongEmail();
    error WrongAddress();
    error EmptySub();
    error WrongSub();
    error WrongChain();
    error WrongVerifier();
    /// A value the circuit cannot carry at all. `max` is the circuit's width,
    /// so a Google address longer than 62 bytes can never bind here — the same
    /// cap `HandleNormalizer` applies to an email.
    error TooLongForCircuit(uint256 length, uint256 max);
    /// A NUL inside a value the circuit zero-pads. See `_pad`.
    error EmbeddedNul();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, address honkVerifier_, address jwksRoots_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _setTrust(honkVerifier_, jwksRoots_);
    }

    /// @notice Replace the circuit verifier or the root list.
    function setTrust(address honkVerifier_, address jwksRoots_) external onlyOwner {
        _setTrust(honkVerifier_, jwksRoots_);
    }

    function _setTrust(address honkVerifier_, address jwksRoots_) private {
        if (honkVerifier_ == address(0) || jwksRoots_ == address(0)) revert ZeroAddress();
        honkVerifier = IHonkVerifier(honkVerifier_);
        jwksRoots = IJwksRoots(jwksRoots_);
    }

    function platformName() external pure override returns (string memory) {
        return "accounts.google.com";
    }

    /// @inheritdoc IIdentityVerifier
    function verify(bytes calldata proof) external view override returns (IdentityClaim memory claim) {
        UserProof memory u = abi.decode(proof, (UserProof));

        if (u.publicInputs.length != TOTAL_PUBLIC_INPUTS) revert WrongPublicInputCount();

        if (!honkVerifier.verify(u.honkProof, u.publicInputs)) revert BadHonkProof();

        // Public-input layout (mirrors the circuit):
        //   [0..18)  modulus limbs
        //   [18..20) email packed (62 bytes)
        //   [20..22) nonce packed (62 bytes)
        //   [22]     sub packed (31 bytes, JWT `sub`)
        //   [23]     exp
        //   [24..26) SHA-256(aud) — NOT checked here, see the contract comment
        //   [26]     chain_id
        //   [27]     the contract that will verify — this one
        bytes memory packed = new bytes(18 * 32);
        for (uint256 i = 0; i < 18; i++) {
            bytes32 v = u.publicInputs[i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), v)
            }
        }
        uint256 modExpiry = jwksRoots.trustedHashExpiresAt(keccak256(packed));
        if (modExpiry == 0 || block.timestamp >= modExpiry) revert UntrustedModulus();

        uint256 jwtExp = uint256(u.publicInputs[23]);
        if (jwtExp + CLOCK_SKEW_GRACE <= block.timestamp) revert JwtExpired();
        // The claim carries a uint64. Narrowing silently would turn a value
        // past that range into a small one that reads as plausible, and the
        // naming contract's clamp on future observations would see the
        // narrowed number rather than the one the circuit proved.
        if (jwtExp > type(uint64).max) revert ExpiryOutOfRange(jwtExp);

        {
            (bytes32 e0, bytes32 e1) = _pack62(_pad(bytes(u.email), 62));
            if (u.publicInputs[18] != e0 || u.publicInputs[19] != e1) revert WrongEmail();
        }

        // The address the token was minted for, carried inside the
        // Google-signed `nonce`. Issuer-attested rather than prover-chosen,
        // which is why this platform needs no separate target field.
        //
        // WHICH address it is depends on the flow, and the token does not say.
        // The browser packs the wallet when linking and the ephemeral session
        // signer when registering, and the two produce the same token shape —
        // so unlike X and GitHub, whose registration proofs carry a zero wallet
        // that `IdentityNames` refuses, nothing on chain separates them. A name
        // bound from a registration token would point at a key the browser
        // discards, so binding must use the link flow. The field is called
        // `sessionKey` because that is the circuit's name for it, not because
        // it is always a session key.
        {
            (bytes32 n0, bytes32 n1) = _pack62(_pad(_addressToAscii(u.sessionKey), 62));
            if (u.publicInputs[20] != n0 || u.publicInputs[21] != n1) revert WrongAddress();
        }

        {
            if (bytes(u.sub).length == 0) revert EmptySub();
            if (u.publicInputs[22] != _pack31(_pad(bytes(u.sub), 31))) revert WrongSub();
        }

        if (uint256(u.publicInputs[26]) != block.chainid) revert WrongChain();
        if (uint256(u.publicInputs[27]) != uint256(uint160(address(this)))) revert WrongVerifier();

        // `exp`, not an issuance time: the circuit exposes no `iat`. It is
        // Google-set and monotone in issuance, so it orders proofs correctly —
        // but it reads roughly an hour ahead, which is why the naming contract
        // takes a per-platform allowance for observations in the future.
        return IdentityClaim({userId: u.sub, handle: u.email, target: u.sessionKey, observedAt: uint64(jwtExp)});
    }

    // ─── Packing, mirroring the circuit ─────────────────────────────

    /// @dev Zero-pad to a fixed width, refusing a NUL that came in.
    ///
    ///      The padding is what makes the check on the packed value work at
    ///      all, and it is also what would break it. `"123"` and `"123\0"`
    ///      pad to the same 31 bytes, so without this a caller could re-submit
    ///      a valid proof under a `sub` with NULs appended: `verify` would pass
    ///      and the binding would land on a node no reader can name, because
    ///      every reader asks for the `sub` Google actually issued. Refusing
    ///      NUL makes the padded form name exactly one input again.
    ///
    ///      Nothing legitimate is lost: neither a `sub` nor an email address
    ///      contains a NUL, and the circuit could not carry one either.
    function _pad(bytes memory s, uint256 width) internal pure returns (bytes memory out) {
        if (s.length > width) revert TooLongForCircuit(s.length, width);
        out = new bytes(width);
        for (uint256 i = 0; i < s.length; i++) {
            if (s[i] == 0) revert EmbeddedNul();
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

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to replace the circuit verifier or
    ///      the root list, and Google's keys expire.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
