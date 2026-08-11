// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IdentityClaim, IIdentityVerifier} from "../IIdentityVerifier.sol";

/// @notice A verifier that returns whatever a test stages.
///
/// @dev This is what lets the contract be tested in full before any provider
///      work exists. Every rule the contract owns — the target check, the
///      watermark, normalization, the two mappings — is independent of how a
///      proof is verified, so proving it here proves it for every provider.
contract MockIdentityVerifier is IIdentityVerifier {
    IdentityClaim private _claim;
    bool private _shouldRevert;
    string private _name;

    constructor(string memory name_) {
        _name = name_;
    }

    function stage(string memory userId, string memory handle, address target, uint64 observedAt) external {
        _claim = IdentityClaim({userId: userId, handle: handle, target: target, observedAt: observedAt});
    }

    function setRevert(bool value) external {
        _shouldRevert = value;
    }

    function verify(bytes calldata) external view override returns (IdentityClaim memory) {
        require(!_shouldRevert, "verifier rejected the proof");
        return _claim;
    }

    function platformName() external view override returns (string memory) {
        return _name;
    }
}
