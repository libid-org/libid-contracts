// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {LibDiamond} from "../diamond/libraries/LibDiamond.sol";
import {IDiamondCut} from "../diamond/interfaces/IDiamondCut.sol";
import {IDiamondLoupe} from "../diamond/interfaces/IDiamondLoupe.sol";
import {IERC173} from "../diamond/interfaces/IERC173.sol";

import {LibCoreStorage} from "./storage/LibCoreStorage.sol";
import {LibTemplateStorage} from "./storage/LibTemplateStorage.sol";
import {LibTemplate} from "./libraries/LibTemplate.sol";
import {ZeroAddress, AlreadyInitialized} from "./BankErrors.sol";

/// @title BankInit — one-shot diamond initializer (run via diamondCut delegatecall).
/// @dev Runs in the diamond's storage context: sets the trusted-party pointers,
///      primes the reentrancy guard, registers ERC-165 interface ids, and seeds
///      the honor templates + resource/web prefixes (mirrors the old
///      `Bank.initialize`). Fresh deploy — no legacy state to preserve.
contract BankInit {
    function init(address notary, address backend, address registry) external {
        if (notary == address(0) || backend == address(0) || registry == address(0)) revert ZeroAddress();

        LibCoreStorage.CoreStorage storage cs = LibCoreStorage.store();
        // One-shot: a later owner diamondCut re-delegatecalling init would otherwise
        // silently overwrite the trusted-party pointers and append duplicate templates.
        if (cs.initialized) revert AlreadyInitialized();
        cs.initialized = true;
        cs.notary = notary;
        cs.backend = backend;
        cs.registry = registry;
        cs.reentrancyStatus = 1; // not-entered (nonReentrant treats 2 as entered)

        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        ds.supportedInterfaces[type(IERC165).interfaceId] = true;
        ds.supportedInterfaces[type(IDiamondCut).interfaceId] = true;
        ds.supportedInterfaces[type(IDiamondLoupe).interfaceId] = true;
        ds.supportedInterfaces[type(IERC173).interfaceId] = true;

        // Honor templates (mirror the old Bank.initialize).
        LibTemplate.addTemplate("api.github.com", "@dyaka-agent honor @{recipient} with {amount} of {token}");
        LibTemplate.addTemplate("api.github.com", "@dyaka-agent honor @{recipient} with {amount} {token}");
        LibTemplate.addTemplate("api.x.com", "@dyaka_agent honor @{recipient} with {amount} of {token}");
        LibTemplate.addTemplate("api.x.com", "@dyaka_agent honor @{recipient} with {amount} {token}");
        // Recipient-less variants (recipient inferred off-chain from the reply/quote
        // parent). X only: GitHub reply-target id leaves aren't supplied yet, so
        // advertising the syntax on-chain would only revert. Phase 2.
        LibTemplate.addTemplate("api.x.com", "@dyaka_agent honor with {amount} of {token}");
        LibTemplate.addTemplate("api.x.com", "@dyaka_agent honor with {amount} {token}");

        LibTemplateStorage.TemplateStorage storage tls = LibTemplateStorage.store();
        tls.resourceTypePrefixes[keccak256("issue_comment")] = "/repos/";
        tls.resourceTypePrefixes[keccak256("pr_comment")] = "/repos/";
        tls.resourceTypePrefixes[keccak256("pr_review")] = "/repos/";
        tls.resourceTypePrefixes[keccak256("issue_body")] = "/repos/";
        tls.resourceTypePrefixes[keccak256("discussion_comment")] = "/graphql";
        tls.resourceTypePrefixes[keccak256("tweet")] = "/2/tweets";

        tls.platformWebPrefixes[keccak256("api.github.com")] = "https://github.com/";
        tls.platformWebPrefixes[keccak256("api.x.com")] = "https://x.com/";
    }
}
