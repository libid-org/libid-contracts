// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {GoogleOidcVerifier, IVerifier} from "../GoogleOidcVerifier.sol";
import {HonkVerifier} from "../Verifier.sol";

interface IRegistrySetOidc {
    function setOidcVerifier(string calldata platform, address verifier) external;
}

/**
 * Deploy the OIDC verifier stack (HonkVerifier + GoogleOidcVerifier) and
 * wire `Registry.setOidcVerifier("www.googleapis.com", …)`.
 *
 * Runs under the `oidc` Foundry profile (via_ir=false).
 *
 * Usage:
 *   FOUNDRY_PROFILE=oidc forge script contracts/login/oidc/script/DeployOidc.s.sol \
 *       --rpc-url $RPC_URL --broadcast \
 *       --sig "run(address,address)" $REGISTRY $NOTARY_CONTRACT_ADDR
 *
 * The second argument is the shared Notary CONTRACT (the proxy every
 * consumer points at), not a raw signer key.
 */
contract DeployOidc is Script {
    function run(address registry, address notaryContract) external {
        // DEPLOYER_KEY may arrive with or without a `0x` prefix (dev-start
        // stores it stripped in .env; --private-key injects 64 bare hex
        // chars). Normalize before parsing so `vm.parseUint` accepts it.
        string memory deployerKeyHex = vm.envOr("DEPLOYER_KEY", vm.envOr("PRIVATE_KEY", string("")));
        require(bytes(deployerKeyHex).length > 0, "set DEPLOYER_KEY or PRIVATE_KEY");
        if (bytes(deployerKeyHex).length == 64) {
            deployerKeyHex = string.concat("0x", deployerKeyHex);
        }
        uint256 deployerKey = vm.parseUint(deployerKeyHex);
        address deployer = vm.addr(deployerKey);
        // Google OAuth client id (the JWT `aud`) this verifier accepts. The
        // circuit is application-agnostic, so the deployment is what pins
        // registrations to one app — required, no silent default. Changeable
        // later via GoogleOidcVerifier.setExpectedAudience(clientId).
        string memory gmailClientId = vm.envString("GMAIL_CLIENT_ID");
        require(bytes(gmailClientId).length > 0, "set GMAIL_CLIENT_ID (the accepted Google OAuth client id)");
        console.log("Deployer:   ", deployer);
        console.log("Registry:   ", registry);
        console.log("Notary contract:", notaryContract);
        console.log("Gmail client id:", gmailClientId);

        vm.startBroadcast(deployerKey);

        HonkVerifier honk = new HonkVerifier();
        // UUPS: deploy implementation, then an ERC1967 proxy initialized with it.
        GoogleOidcVerifier googleImpl = new GoogleOidcVerifier();
        ERC1967Proxy googleProxy = new ERC1967Proxy(
            address(googleImpl),
            abi.encodeCall(
                GoogleOidcVerifier.initialize, (IVerifier(address(honk)), deployer, notaryContract, gmailClientId)
            )
        );
        GoogleOidcVerifier google = GoogleOidcVerifier(address(googleProxy));

        IRegistrySetOidc(registry).setOidcVerifier("www.googleapis.com", address(google));

        vm.stopBroadcast();

        console.log("---");
        console.log("HONK_VERIFIER_ADDRESS=", address(honk));
        console.log("GOOGLE_OIDC_VERIFIER_ADDRESS=", address(google));
    }
}
