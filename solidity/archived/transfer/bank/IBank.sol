// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ResourceInfo, SenderInfo, BackendSig, NotaryTlsProof} from "./BankTypes.sol";

/// @title IBank — the Bank diamond's full external surface (Vault + Admin + Transfer
///        facets), for callers that address the diamond as one contract (tests,
///        scripts, the frontend). Structs come from `BankTypes`.
interface IBank {
    // ── Vault ────────────────────────────────────────────────────────────
    function deposit(
        string calldata platform,
        string calldata handle,
        string calldata userId,
        address token,
        uint256 amount
    ) external payable;
    function withdraw(address recipient, address token, uint256 amount) external;
    function balanceOf(address wallet, address token) external view returns (uint256);
    function balanceOf(string calldata platform, string calldata handle, string calldata userId, address token)
        external
        view
        returns (uint256);
    function balanceOfTotal(address wallet, address token) external view returns (uint256);
    function balanceOfTotal(string calldata platform, string calldata handle, string calldata userId, address token)
        external
        view
        returns (uint256);
    function registeredBalances(address wallet, address token) external view returns (uint256);
    function unregisteredBalances(bytes32 key, address token) external view returns (uint256);
    function identityHash(string calldata domain, string calldata username) external pure returns (bytes32);

    // ── Admin ────────────────────────────────────────────────────────────
    function pause() external;
    function unpause() external;
    function setRegistry(address registry) external;
    function registerToken(string calldata name, address token) external;
    function unregisterToken(string calldata name) external;
    function resolveToken(string calldata name) external view returns (address);
    function getRegisteredTokens() external view returns (address[] memory);
    function setPlatformTemplate(string calldata platform, string calldata newTemplate) external;
    function clearPlatformTemplates(string calldata platform) external;
    function platformTemplateCount(string calldata platform) external view returns (uint256);
    function getPlatformTemplate(string calldata platform, uint256 index) external view returns (string memory);
    function getTemplateParts(string calldata platform, uint256 index)
        external
        view
        returns (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix);
    function setResourceTypePrefix(string calldata resourceType, string calldata prefix) external;
    function setPlatformWebPrefix(string calldata platform, string calldata prefix) external;
    function getPlatformWebPrefix(string calldata platform) external view returns (string memory);
    function registry() external view returns (address);
    function paused() external view returns (bool);
    function tokenName(address token) external view returns (string memory);

    // ── Transfer ─────────────────────────────────────────────────────────
    function verifyProof(
        ResourceInfo calldata resource,
        SenderInfo calldata sender,
        bytes calldata revealedSubsection,
        NotaryTlsProof calldata notaryTlsProof,
        BackendSig calldata backendSigData,
        string calldata receiverUserId
    ) external view returns (bool);
    function webTransferV2(
        ResourceInfo calldata resource,
        SenderInfo calldata sender,
        bytes calldata revealedSubsection,
        NotaryTlsProof calldata notaryTlsProof,
        BackendSig calldata backendSigData,
        string calldata receiverHandle,
        string calldata receiverUserId,
        string calldata tokenName_,
        string calldata amountStr,
        uint256 amount,
        string calldata sourceUrl
    ) external;
    function webTransferV2(
        ResourceInfo calldata resource,
        SenderInfo calldata sender,
        bytes calldata revealedSubsection,
        NotaryTlsProof calldata notaryTlsProof,
        BackendSig calldata backendSigData,
        string calldata receiverHandle,
        string calldata receiverUserId,
        address token,
        string calldata amountStr,
        uint256 amount,
        string calldata sourceUrl
    ) external;
    function transfer_within(
        string calldata receiverPlatform,
        string calldata receiverHandle,
        string calldata receiverUserId,
        address token,
        uint256 amount
    ) external;
}
