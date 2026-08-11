// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LibTemplateStorage — honor-template + resource/web-prefix config.
/// @dev Everything the template-matching path reads: per-platform template
///      strings, their parsed parts, and the resource-type / web-URL prefixes.
///      Its own namespaced slot — isolated from token registry and escrow.
library LibTemplateStorage {
    bytes32 internal constant STORAGE_POSITION = keccak256("dyaka.bank.template.v1");

    /// Parsed honor-template parts (parallel to `platformTemplates[key][i]`).
    struct TemplateParts {
        string prefix; // text before {recipient} (or full literal for simple templates)
        string afterRecipient; // text between {recipient} and {amount}
        string afterAmount; // text between {amount} and {token}
        string suffix; // text after {token}
        bool hasPlaceholders; // true when the template has {recipient}/{amount}/{token}
    }

    struct TemplateStorage {
        mapping(bytes32 => string[]) platformTemplates; // keccak(platform) → template strings
        mapping(bytes32 => TemplateParts[]) templateParts; // parallel parsed parts
        mapping(bytes32 => string) resourceTypePrefixes; // keccak(resourceType) → request-path prefix
        mapping(bytes32 => string) platformWebPrefixes; // keccak(platform) → web URL prefix
    }

    function store() internal pure returns (TemplateStorage storage ts) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            ts.slot := position
        }
    }
}
