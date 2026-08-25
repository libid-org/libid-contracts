// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../contracts/login/Registry.sol";
import {WalletFactory} from "../contracts/login/WalletFactory.sol";
import {WebWallet} from "../contracts/login/WebWallet.sol";
import {IBank} from "../contracts/transfer/bank/IBank.sol";
import {BankDiamondDeployer} from "../contracts/transfer/script/BankDiamondDeployer.sol";
import {Notary} from "../contracts/notary/Notary.sol";
import {MockERC20} from "../contracts/transfer/MockERC20.sol";
import {XHonkVerifier} from "../contracts/login/zk/XHonkVerifier.sol";
import {XZkVerifier, IHonkVerifier} from "../contracts/login/zk/XZkVerifier.sol";
import {IZkSessionVerifier} from "../contracts/login/zk/IZkSessionVerifier.sol";
import {IdentityNames} from "../contracts/identity/IdentityNames.sol";
import {HandleVectors} from "../contracts/identity/HandleVectors.sol";
import {IdentityJwksRoots} from "../contracts/identity/IdentityJwksRoots.sol";

/// @notice Deploy full stack to any EVM chain.
///
/// Usage:
///   forge script contracts/script/Deploy.s.sol \
///     --rpc-url http://127.0.0.1:8545 \
///     --broadcast \
///     --private-key $PRIVATE_KEY
///
/// Optional env:
///   NOTARY_ADDRESS   — notary signing key address.
///   BACKEND_ADDRESS  — backend signing key address.
contract Deploy is Script, BankDiamondDeployer {
    function run() external {
        string memory deployerKeyHex = vm.envOr("DEPLOYER_KEY", vm.envOr("PRIVATE_KEY", string("")));
        require(bytes(deployerKeyHex).length > 0, "set DEPLOYER_KEY or PRIVATE_KEY");
        // Forge injects PRIVATE_KEY without 0x prefix via --private-key flag.
        if (bytes(deployerKeyHex).length == 64) {
            deployerKeyHex = string.concat("0x", deployerKeyHex);
        }
        uint256 deployerKey = vm.parseUint(deployerKeyHex);
        address deployer = vm.addr(deployerKey);
        address notaryAddr = vm.envOr("NOTARY_ADDRESS", deployer);
        address backendAddr = vm.envOr("BACKEND_ADDRESS", deployer);

        vm.startBroadcast(deployerKey);

        // 0. Notary (UUPS proxy) — the ONE notary-attestation verifier every
        //    other contract points at. Deployed first so its proxy address can
        //    be wired into every consumer's initialize. Key rotation is
        //    `notaryContract.setNotary`; a proof-system change is a UUPS
        //    upgrade of this proxy alone.
        Notary notaryImpl = new Notary();
        Notary notaryContract = Notary(
            address(new ERC1967Proxy(address(notaryImpl), abi.encodeCall(Notary.initialize, (deployer, notaryAddr))))
        );

        // 1. WebWallet implementation (beacon target)
        WebWallet walletImpl = new WebWallet();

        // 2. WalletFactory (UUPS proxy)
        WalletFactory factoryImpl = new WalletFactory();
        WalletFactory factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(factoryImpl),
                    abi.encodeCall(WalletFactory.initialize, (deployer, address(walletImpl), address(0)))
                )
            )
        );

        // 4. Registry (UUPS proxy) — unified MPC + ZK registration
        Registry registryImpl = new Registry();
        Registry registry = Registry(
            address(
                new ERC1967Proxy(
                    address(registryImpl),
                    abi.encodeCall(
                        Registry.initialize, (address(notaryContract), backendAddr, address(factory), deployer)
                    )
                )
            )
        );

        // 5. Bank (EIP-2535 diamond) — facets + BankInit (seeds templates/prefixes).
        //    Same BANK_CONTRACT_ADDRESS surface as before; the diamond keeps every
        //    Bank function signature, so backend/frontend need only the new address.
        IBank bank = IBank(deployBankDiamond(deployer, address(notaryContract), backendAddr, address(registry)));

        // 6. XHonkVerifier — single UltraHonk verifier for the merged
        //    X dual-session proof. Called from XZkVerifier.
        XHonkVerifier xHonk = new XHonkVerifier();

        // 7. MockERC20 dev token
        MockERC20 devToken = new MockERC20("DEV Token", "DEV");

        // 8. Wire factory <-> registry
        factory.setRegistry(address(registry));

        // 9. Register dev token in Bank. Name must include the "$" prefix —
        //    the comment parser keeps it (e.g. "$DEV") and the bot sends that
        //    exact string as tokenName_, so the on-chain name must match.
        bank.registerToken("$DEV", address(devToken));

        // 10. Mint dev tokens to deployer for testing (1M tokens)
        devToken.mint(deployer, 1_000_000 ether);

        // 11. Deploy XZkVerifier (UUPS proxy) and register it with Registry
        //     under the "api.x.com" platform. One X app serves both the browser
        //     ZK flow and the backend OAuth flow, so the verifier's client_id is
        //     just $X_CLIENT_ID (must match the browser's NEXT_PUBLIC_X_CLIENT_ID).
        string memory xClientIdStr = vm.envOr("X_CLIENT_ID", string(""));
        address xZkVerifierAddr;
        if (bytes(xClientIdStr).length > 0) {
            XZkVerifier xZkImpl = new XZkVerifier();
            xZkVerifierAddr = address(
                new ERC1967Proxy(
                    address(xZkImpl),
                    abi.encodeCall(
                        XZkVerifier.initialize,
                        (
                            deployer,
                            address(notaryContract),
                            IHonkVerifier(address(xHonk)),
                            bytes(xClientIdStr),
                            "/2/users/me",
                            "\"username\":\"",
                            "api.x.com"
                        )
                    )
                )
            );
            registry.setZkVerifier("api.x.com", IZkSessionVerifier(xZkVerifierAddr));
        }

        // 13. Seed supported platforms (mirrors deploy.rs platform_configs)
        registry.setPlatform("api.x.com", "/2/users/me", "\"username\":\"", "\"id\":\"", "\"");
        registry.setPlatform("api.github.com", "/user", "\"login\":\"", "\"id\":", ",");
        registry.setPlatform("discord.com", "/api/users/@me", "\"username\":\"", "\"id\":\"", "\"");
        registry.setPlatform("www.googleapis.com", "/oauth2/v2/userinfo", "\"email\": \"", "\"id\": \"", "\"");

        // 14. The naming system: one contract holding the names, and an
        //     adapter per platform that reads the proof that platform's login
        //     already produces. Nothing here changes how anybody logs in.
        //
        //     The future allowance differs by platform because they report on
        //     different scales. A notary states wall-clock time, so an X or
        //     GitHub observation is never ahead; a Google claim carries the
        //     token's `exp`, roughly an hour past issuance, because the circuit
        //     exposes no `iat`.
        IdentityNames namesImpl = new IdentityNames();
        address identityNamesAddr =
            address(new ERC1967Proxy(address(namesImpl), abi.encodeCall(IdentityNames.initialize, (deployer))));
        IdentityNames names = IdentityNames(identityNamesAddr);

        // A keyspace per platform, and nothing more. Wiring a verifier is
        // `CeremonyProofVerifier.setVerifier`, and a Platform Verifier needs
        // the ceremony circuit's artifact and its code hash -- neither of which
        // this script has until that release lands.
        _wireIdentityPlatform(names, HandleVectors.PLATFORM_X);
        _wireIdentityPlatform(names, HandleVectors.PLATFORM_GITHUB);
        _wireIdentityPlatform(names, HandleVectors.PLATFORM_GOOGLE);

        // The JWKS root list is the naming system's own. Google's Platform
        // Verifier reads the trusted moduli through it, and nothing is trusted
        // until a notarized reading of Google's JWKS lands.
        IdentityJwksRoots rootsImpl = new IdentityJwksRoots();
        address jwksRootsAddr = address(
            new ERC1967Proxy(
                address(rootsImpl), abi.encodeCall(IdentityJwksRoots.initialize, (deployer, address(notaryContract)))
            )
        );

        vm.stopBroadcast();

        console.log("=== Deployment complete ===");
        console.log("Deployer:               ", deployer);
        console.log("WEBWALLET_IMPL=         ", address(walletImpl));
        console.log("WALLET_FACTORY_ADDRESS= ", address(factory));
        console.log("REGISTRY_CONTRACT_ADDRESS= ", address(registry));
        console.log("BANK_CONTRACT_ADDRESS= ", address(bank));
        console.log("DEV_TOKEN_ADDRESS= ", address(devToken));
        console.log("NOTARY_CONTRACT_ADDRESS= ", address(notaryContract));
        console.log("XHonkVerifier:          ", address(xHonk));
        console.log("XZkVerifier:            ", xZkVerifierAddr);
        console.log("IDENTITY_NAMES_ADDRESS= ", identityNamesAddr);
        console.log("IDENTITY_JWKS_ROOTS_ADDRESS= ", jwksRootsAddr);
        console.log("NOTE: no Platform Verifier is wired. Register one with");
        console.log("      CeremonyProofVerifier.setVerifier once the ceremony");
        console.log("      circuit artifacts are released.");
        // Nothing is trusted until a notarized reading of Google's JWKS lands.
        // Until then every Google claim reverts `UntrustedModulus`, which reads
        // as a bad proof rather than an unseeded list.
        console.log("NOTE: point a JWKS rotation listener at IDENTITY_JWKS_ROOTS_ADDRESS");
        console.log("      before Google names work. The trust list starts empty.");
    }

    /// @dev Give a platform its keyspace.
    ///
    ///      One helper rather than the call spelled out per platform: the rules
    ///      come from the generated table keyed by platform id, so a new
    ///      platform is one line here and cannot pick up a neighbour's rules by
    ///      a copy-paste slip.
    function _wireIdentityPlatform(IdentityNames names, bytes32 platformId) internal {
        names.setPlatform(platformId, HandleVectors.rulesFor(platformId));
    }
}
