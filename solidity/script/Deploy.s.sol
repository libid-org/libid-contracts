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
import {IIdentityVerifier} from "../contracts/identity/IIdentityVerifier.sol";
import {HandleVectors} from "../contracts/identity/HandleVectors.sol";
import {XIdentityVerifier} from "../contracts/identity/XIdentityVerifier.sol";
import {GitHubIdentityVerifier} from "../contracts/identity/GitHubIdentityVerifier.sol";
import {GoogleIdentityVerifier} from "../contracts/identity/GoogleIdentityVerifier.sol";
import {IdentityJwksRoots} from "../contracts/identity/IdentityJwksRoots.sol";
import {HandleEscrow} from "../contracts/escrow/HandleEscrow.sol";
import {IIdentityNames} from "../contracts/escrow/IIdentityNames.sol";

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

        // The naming system's own X verifier. It reuses the login stack's Honk
        // verifier contract — a pure circuit checker, stateless and owned by
        // nobody — but nothing else: its notary key and its view of the
        // exchange are its own, and the notary attests to IT.
        //
        // Unconditional, unlike `XZkVerifier` above. That one needs an OAuth
        // client id and is skipped without one; this one checks no client id,
        // so gating it on `X_CLIENT_ID` would mean X names silently do not
        // exist on a naming-only deployment. The Rust deployer gates X on its
        // own `--with-x` flag, and the two have to agree on when X names exist.
        XIdentityVerifier xIdImpl = new XIdentityVerifier();
        address xIdentityAddr = address(
            new ERC1967Proxy(
                address(xIdImpl),
                abi.encodeCall(
                    XIdentityVerifier.initialize,
                    (
                        deployer,
                        address(notaryContract),
                        address(xHonk),
                        XIdentityVerifier.ResponseShape(
                            "api.x.com", "/2/users/me", "\"username\":\"", "\"id\":\"", "\""
                        )
                    )
                )
            )
        );
        _wireIdentityPlatform(names, HandleVectors.PLATFORM_X, xIdentityAddr);

        // The naming system's own GitHub verifier. It holds its own keys and
        // its own view of GitHub's response, and the notary attests to IT — so
        // the naming system's notary deployment carries this address, not the
        // wallet Registry's.
        GitHubIdentityVerifier ghIdImpl = new GitHubIdentityVerifier();
        address githubIdentityAddr = address(
            new ERC1967Proxy(
                address(ghIdImpl),
                abi.encodeCall(
                    GitHubIdentityVerifier.initialize,
                    (
                        deployer,
                        address(notaryContract),
                        // GitHub's id is a bare number ending at a comma.
                        GitHubIdentityVerifier.ResponseShape("/user", "\"login\":\"", "\"id\":", ",")
                    )
                )
            )
        );
        _wireIdentityPlatform(names, HandleVectors.PLATFORM_GITHUB, githubIdentityAddr);

        // Google needs the circuit's Honk verifier, which the OIDC script
        // deploys, so this is wired only when that address is supplied. The
        // JWKS root list is the naming system's own and is deployed here.
        address googleHonkAddr = vm.envOr("GOOGLE_HONK_VERIFIER_ADDRESS", address(0));
        address googleIdentityAddr;
        address jwksRootsAddr;
        if (googleHonkAddr != address(0)) {
            IdentityJwksRoots rootsImpl = new IdentityJwksRoots();
            jwksRootsAddr = address(
                new ERC1967Proxy(
                    address(rootsImpl),
                    abi.encodeCall(IdentityJwksRoots.initialize, (deployer, address(notaryContract)))
                )
            );

            GoogleIdentityVerifier gIdImpl = new GoogleIdentityVerifier();
            googleIdentityAddr = address(
                new ERC1967Proxy(
                    address(gIdImpl),
                    abi.encodeCall(GoogleIdentityVerifier.initialize, (deployer, googleHonkAddr, jwksRootsAddr))
                )
            );
            _wireIdentityPlatform(names, HandleVectors.PLATFORM_GOOGLE, googleIdentityAddr);
        }

        // 15. The handle escrow: value sent to a name before anybody claims it.
        //
        //     Wired to the naming proxy and never repointed — moving it would
        //     redirect every entitlement it holds, so there is no setter and
        //     changing it is an upgrade.
        HandleEscrow escrowImpl = new HandleEscrow();
        address handleEscrowAddr = address(
            new ERC1967Proxy(
                address(escrowImpl),
                abi.encodeCall(HandleEscrow.initialize, (deployer, IIdentityNames(identityNamesAddr)))
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
        console.log("X_IDENTITY_VERIFIER_ADDRESS= ", xIdentityAddr);
        console.log("GITHUB_IDENTITY_VERIFIER_ADDRESS= ", githubIdentityAddr);
        console.log("GOOGLE_IDENTITY_VERIFIER_ADDRESS= ", googleIdentityAddr);
        console.log("IDENTITY_JWKS_ROOTS_ADDRESS= ", jwksRootsAddr);
        console.log("HANDLE_ESCROW_ADDRESS= ", handleEscrowAddr);
        if (googleIdentityAddr != address(0)) {
            // Nothing is trusted until a notarized reading of Google's JWKS
            // lands. Until then every Google bind reverts `UntrustedModulus`,
            // which reads as a bad proof rather than an unseeded list.
            console.log("NOTE: point a JWKS rotation listener at IDENTITY_JWKS_ROOTS_ADDRESS");
            console.log("      before Google names work. The trust list starts empty.");
        }
    }

    /// @dev Give a platform its keyspace and its first verifier.
    ///
    ///      One helper rather than the pair spelled out per platform: the rules
    ///      and the allowance both come from the generated table keyed by
    ///      platform id, so a new platform is one line here and cannot pick up
    ///      a neighbour's rules by a copy-paste slip.
    function _wireIdentityPlatform(IdentityNames names, bytes32 platformId, address verifier) internal {
        names.setPlatform(platformId, HandleVectors.rulesFor(platformId));
        names.setVerifier(
            platformId,
            names.INITIAL_VERSION(),
            IIdentityVerifier(verifier),
            HandleVectors.futureAllowanceFor(platformId)
        );
    }
}
