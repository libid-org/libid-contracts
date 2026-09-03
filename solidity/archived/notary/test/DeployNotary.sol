// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Notary} from "../Notary.sol";

/// Test-only helper: a Notary behind a fresh ERC1967 proxy, initialized with
/// `owner_` and `signer_`. Every suite that needs a notary check wires one of
/// these, so the wiring lives in one place.
function deployNotary(address owner_, address signer_) returns (Notary) {
    Notary impl = new Notary();
    return Notary(address(new ERC1967Proxy(address(impl), abi.encodeCall(Notary.initialize, (owner_, signer_)))));
}
