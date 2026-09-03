// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {BankDiamondDeployer} from "./BankDiamondDeployer.sol";

/// @notice Deploy a fresh Bank diamond against an EXISTING Notary contract +
///         Registry (the migration seeds it afterwards).
///
/// Usage:
///   forge script contracts/script/DeployBankDiamond.s.sol \
///     --rpc-url $RPC_URL --broadcast --private-key $PRIVATE_KEY
///
/// Env:
///   NOTARY_CONTRACT_ADDRESS  — the shared Notary contract (Bank verifies notary attestations through it).
///   BACKEND_ADDRESS          — backend signer address.
///   REGISTRY_CONTRACT_ADDRESS — Registry contract (identity resolution).
contract DeployBankDiamond is Script, BankDiamondDeployer {
    function run() external {
        string memory keyHex = vm.envOr("DEPLOYER_KEY", vm.envOr("PRIVATE_KEY", string("")));
        require(bytes(keyHex).length > 0, "set DEPLOYER_KEY or PRIVATE_KEY");
        if (bytes(keyHex).length == 64) keyHex = string.concat("0x", keyHex);
        uint256 deployerKey = vm.parseUint(keyHex);
        address deployer = vm.addr(deployerKey);

        address notaryContract = vm.envAddress("NOTARY_CONTRACT_ADDRESS");
        address backend = vm.envOr("BACKEND_ADDRESS", deployer);
        address registry = vm.envAddress("REGISTRY_CONTRACT_ADDRESS");

        vm.startBroadcast(deployerKey);
        address diamond = deployBankDiamond(deployer, notaryContract, backend, registry);
        vm.stopBroadcast();

        console.log("=== Bank diamond deployed ===");
        console.log("Owner:                 ", deployer);
        console.log("BANK_CONTRACT_ADDRESS= ", diamond);
    }
}
