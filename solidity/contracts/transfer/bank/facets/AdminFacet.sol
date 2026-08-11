// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BankModifiers} from "../BankModifiers.sol";
import {LibCoreStorage} from "../storage/LibCoreStorage.sol";
import {LibTokenStorage} from "../storage/LibTokenStorage.sol";
import {LibTemplateStorage} from "../storage/LibTemplateStorage.sol";
import {LibTemplate} from "../libraries/LibTemplate.sol";
import {LibString} from "../libraries/LibString.sol";
import {ZeroAddress, EmptyName, AlreadyRegistered, NotRegistered} from "../BankErrors.sol";

/// @title AdminFacet — owner-gated Bank configuration.
/// @dev Token registry, honor-template admin, resource-type / web prefixes, the
///      Registry pointer, and pause. Reads/writes the token/template/core storage
///      concerns; owner is the diamond owner (via BankModifiers).
contract AdminFacet is BankModifiers {
    event Paused(address account);
    event Unpaused(address account);
    event RegistrySet(address indexed oldRegistry, address indexed newRegistry);
    event TokenRegistered(string name, address indexed token);
    event TokenUnregistered(string name, address indexed token);

    // ── Lifecycle ────────────────────────────────────────────────────────

    /// @notice Pause state-changing entrypoints (emergency stop / migration gate).
    function pause() external onlyOwner {
        LibCoreStorage.store().paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Resume after a pause.
    function unpause() external onlyOwner {
        LibCoreStorage.store().paused = false;
        emit Unpaused(msg.sender);
    }

    // ── Registry pointer ─────────────────────────────────────────────────

    function setRegistry(address _registry) external onlyOwner {
        if (_registry == address(0)) revert ZeroAddress();
        LibCoreStorage.CoreStorage storage cs = LibCoreStorage.store();
        address old = cs.registry;
        cs.registry = _registry;
        if (old != _registry) emit RegistrySet(old, _registry);
    }

    // ── Token registry ───────────────────────────────────────────────────

    function registerToken(string calldata name, address token) external onlyOwner {
        if (bytes(name).length == 0) revert EmptyName();
        LibTokenStorage.TokenStorage storage ts = LibTokenStorage.store();
        bytes32 key = _nameKey(name);
        // Name taken? `tokenByName` covers ERC-20s, but the NATIVE asset keeps
        // address(0) there (indistinguishable from unset), so a native-registered
        // name would slip through — also reject a name already held by the native
        // (else registering it for an ERC-20 hijacks the name / desyncs the registry).
        if (ts.tokenByName[key] != address(0)) revert AlreadyRegistered();
        // Case-INSENSITIVE for the native: webTransferV2 resolves the native asset
        // via LibString.caseInsensitiveEqual, so a case variant (native "TIA" then
        // ERC-20 "tia") must be rejected here too — else the registry desyncs and a
        // by-name honor can settle the wrong asset.
        if (
            bytes(ts.tokenName[address(0)]).length != 0
                && LibString.caseInsensitiveEqual(ts.tokenName[address(0)], name)
        ) {
            revert AlreadyRegistered();
        }
        // Address already registered (blocks a second name for the same token → dup
        // entry, and a second native registration).
        if (bytes(ts.tokenName[token]).length != 0) revert AlreadyRegistered();
        ts.tokenByName[key] = token;
        ts.tokenName[token] = name;
        ts.registeredTokens.push(token);
        emit TokenRegistered(name, token);
    }

    function unregisterToken(string calldata name) external onlyOwner {
        LibTokenStorage.TokenStorage storage ts = LibTokenStorage.store();
        bytes32 key = _nameKey(name);
        address token = ts.tokenByName[key];
        // token == address(0) is ambiguous: the native asset registered under
        // `name`, or a name that was never registered. It is the native ONLY when
        // the stored native name matches `name` — otherwise revert (don't wipe it).
        if (token == address(0)) {
            string memory nativeName = ts.tokenName[address(0)];
            if (bytes(nativeName).length == 0 || _nameKey(nativeName) != key) revert NotRegistered();
        }
        delete ts.tokenByName[key];
        delete ts.tokenName[token];
        _removeRegisteredToken(ts, token);
        emit TokenUnregistered(name, token);
    }

    function resolveToken(string calldata name) external view returns (address) {
        return LibTokenStorage.store().tokenByName[_nameKey(name)];
    }

    function getRegisteredTokens() external view returns (address[] memory) {
        return LibTokenStorage.store().registeredTokens;
    }

    /// @dev Token-name storage key. NB: case-sensitive — the webTransferV2 token
    ///      lookup is likewise case-sensitive; unifying them case-insensitively is
    ///      blocked by webTransferV2's stack limit (needs a param-struct refactor).
    function _nameKey(string memory name) private pure returns (bytes32) {
        return keccak256(bytes(name));
    }

    /// @dev Swap-pop `token` out of the registeredTokens list (no-op if absent).
    function _removeRegisteredToken(LibTokenStorage.TokenStorage storage ts, address token) private {
        uint256 n = ts.registeredTokens.length;
        for (uint256 i = 0; i < n; i++) {
            if (ts.registeredTokens[i] == token) {
                ts.registeredTokens[i] = ts.registeredTokens[n - 1];
                ts.registeredTokens.pop();
                return;
            }
        }
    }

    // ── Template admin ───────────────────────────────────────────────────

    /// @notice Add a template for a platform (appends to the list).
    function setPlatformTemplate(string calldata platform, string calldata newTemplate) external onlyOwner {
        LibTemplate.addTemplate(platform, newTemplate);
    }

    /// @notice Remove all templates for a platform.
    function clearPlatformTemplates(string calldata platform) external onlyOwner {
        LibTemplateStorage.TemplateStorage storage ts = LibTemplateStorage.store();
        bytes32 key = keccak256(bytes(platform));
        delete ts.platformTemplates[key];
        delete ts.templateParts[key];
    }

    function platformTemplateCount(string calldata platform) external view returns (uint256) {
        return LibTemplateStorage.store().platformTemplates[keccak256(bytes(platform))].length;
    }

    /// @notice The raw stored template string at `index` (verbatim, unparsed).
    function getPlatformTemplate(string calldata platform, uint256 index) external view returns (string memory) {
        return LibTemplateStorage.store().platformTemplates[keccak256(bytes(platform))][index];
    }

    function getTemplateParts(string calldata platform, uint256 index)
        external
        view
        returns (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix)
    {
        LibTemplateStorage.TemplateParts storage parts =
            LibTemplateStorage.store().templateParts[keccak256(bytes(platform))][index];
        return (parts.prefix, parts.afterRecipient, parts.afterAmount, parts.suffix);
    }

    // ── Resource / web prefixes ──────────────────────────────────────────

    function setResourceTypePrefix(string calldata resourceType, string calldata prefix) external onlyOwner {
        LibTemplateStorage.store().resourceTypePrefixes[keccak256(bytes(resourceType))] = prefix;
    }

    function setPlatformWebPrefix(string calldata platform, string calldata prefix) external onlyOwner {
        LibTemplateStorage.store().platformWebPrefixes[keccak256(bytes(platform))] = prefix;
    }

    /// @notice The web-URL prefix bound to a platform ("" if unset).
    function getPlatformWebPrefix(string calldata platform) external view returns (string memory) {
        return LibTemplateStorage.store().platformWebPrefixes[keccak256(bytes(platform))];
    }

    // ── Views (parity with the old Bank public state) ─────────────────────

    /// @notice The Registry pointer used for identity resolution.
    function registry() external view returns (address) {
        return LibCoreStorage.store().registry;
    }

    /// @notice Whether state-changing entrypoints are paused.
    function paused() external view returns (bool) {
        return LibCoreStorage.store().paused;
    }

    /// @notice The registered name for a token address ("" if unregistered).
    function tokenName(address token) external view returns (string memory) {
        return LibTokenStorage.store().tokenName[token];
    }
}
