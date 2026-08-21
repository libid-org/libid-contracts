// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {INotaryService} from "./INotaryService.sol";

/// @title NotaryService
///
/// @notice Authenticates one attestation and charges one fee for it.
///
/// @dev This replaces a verifier that took a digest its caller computed. That
///      shape authenticated a number rather than a session: whatever the caller
///      hashed is what the signature was checked against, and the values the
///      Platform Verifier went on to read were whatever the caller supplied
///      next to it. Deriving the key from the attested data itself is what
///      makes those the signed fields (REQ-COMMON-49).
///
///      It holds several trusted keys rather than one. Rotation must not
///      invalidate attestations already made under the outgoing key, so the
///      incoming key is added, both are trusted for a while, and the outgoing
///      one is removed when nothing outstanding can still be presented under
///      it.
///
///      Fees accrue here and the owner withdraws them, rather than forwarding
///      on each verification. A submission verifying two attestations would
///      otherwise make two external calls inside the verification path, where a
///      hostile or gas-hungry recipient could make an honest submission fail.
///      Nothing is forwarded, so there is nothing to reenter.
contract NotaryService is INotaryService, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    // ─── State ──────────────────────────────────────────────────────

    /// @custom:storage-location erc7201:libid.storage.NotaryService
    struct NotaryServiceStorage {
        /// What one verification costs. One value, read with no arguments, so
        /// it cannot vary by content or principal (REQ-COMMON-34C).
        uint256 fee;
        /// The keys currently trusted. Append-only in spirit: a key is added
        /// before it signs and removed after nothing can still present under it.
        mapping(address => bool) trusted;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.NotaryService")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant NOTARY_SERVICE_STORAGE =
        0x7e0f45e5fb68069046082b9a29aa418cbadf43bb1025c0e2debddab14853f800;

    function _s() private pure returns (NotaryServiceStorage storage $) {
        assembly {
            $.slot := NOTARY_SERVICE_STORAGE
        }
    }

    // ─── Events ─────────────────────────────────────────────────────

    event FeeChanged(uint256 previousFee, uint256 newFee);
    event NotaryTrustChanged(address indexed key, bool trusted);
    event FeesWithdrawn(address indexed to, uint256 amount);

    // ─── Errors ─────────────────────────────────────────────────────

    /// @dev The fee is service-controlled state that can change between
    ///      building a transaction and including it. Failing visibly beats
    ///      silently overcharging the Fee Payer, and leaves no overpayment to
    ///      refund (REQ-COMMON-34E).
    error WrongFee(uint256 required, uint256 provided);
    /// @dev The signature is outside the keys currently held as trusted, or it
    ///      recovers to nothing at all (REQ-COMMON-33A).
    error UntrustedNotary(address recovered);
    error MalformedSignature();
    error ZeroAddress();
    error NothingToWithdraw();
    error WithdrawalFailed(address to, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param owner_  Owns the fee, the trusted set and the upgrade.
    /// @param notary_ The first trusted key.
    /// @param fee_    The launch fee. Zero is allowed: a deployment may meter
    ///                at no charge, and REQ-COMMON-34E still requires an exact
    ///                match, so a caller attaching value to a free service is
    ///                rejected rather than silently donating.
    function initialize(address owner_, address notary_, uint256 fee_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        _setTrust(notary_, true);
        _s().fee = fee_;
        emit FeeChanged(0, fee_);
    }

    // ─── Verification ───────────────────────────────────────────────

    /// @inheritdoc INotaryService
    function verify(bytes calldata attestedData, bytes calldata signature) external payable {
        uint256 required = _s().fee;
        if (msg.value != required) revert WrongFee(required, msg.value);

        // The digest is computed HERE, from the bytes the caller passed, and
        // never accepted from the caller. This one line is the whole point of
        // the contract.
        bytes32 digest = keccak256(attestedData);
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(digest);

        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethHash, signature);
        if (err != ECDSA.RecoverError.NoError) revert MalformedSignature();
        if (!_s().trusted[recovered]) revert UntrustedNotary(recovered);
    }

    /// @inheritdoc INotaryService
    function fee() external view returns (uint256) {
        return _s().fee;
    }

    /// @inheritdoc INotaryService
    function isTrustedNotary(address key) external view returns (bool) {
        return _s().trusted[key];
    }

    // ─── Governance ─────────────────────────────────────────────────

    /// @notice Set what one verification costs.
    /// @dev A raised fee cannot forge or retarget evidence, so this is a
    ///      liveness dependency rather than a soundness one -- but a fee raised
    ///      without bound stops every ceremony for the platforms pinning this
    ///      service until governance selects another.
    function setFee(uint256 fee_) external onlyOwner {
        emit FeeChanged(_s().fee, fee_);
        _s().fee = fee_;
    }

    /// @notice Add or remove a trusted notary key.
    function setNotary(address key, bool trusted_) external onlyOwner {
        _setTrust(key, trusted_);
    }

    /// @notice Withdraw accrued fees.
    function withdraw(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0 || amount > address(this).balance) revert NothingToWithdraw();
        emit FeesWithdrawn(to, amount);
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert WithdrawalFailed(to, amount);
    }

    function _setTrust(address key, bool trusted_) private {
        if (key == address(0)) revert ZeroAddress();
        _s().trusted[key] = trusted_;
        emit NotaryTrustChanged(key, trusted_);
    }

    /// @dev Required by UUPS -- only the owner can upgrade.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to rotate a key, set the fee, or
    ///      withdraw what has accrued.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
