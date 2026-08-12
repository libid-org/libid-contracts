// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../../Registry.sol";
import {WalletFactory} from "../../WalletFactory.sol";
import {WebWallet} from "../../WebWallet.sol";
import {IOidcVerifier} from "../../oidc/IOidcVerifier.sol";
import {deployNotary} from "../../../notary/test/DeployNotary.sol";

// A JWT expiry far in the future but well below uint256 max, so the
// `jwtExp + CLOCK_SKEW_GRACE` freshness check can't overflow.
uint256 constant FUTURE = 4_000_000_000;

/// Stand-in OIDC verifier returning whatever the test set up, so the
/// Registry link dispatcher can be exercised without a real JWT/circuit.
contract StubOidcVerifier is IOidcVerifier {
    string public handle = "alice@gmail.com";
    address public nonceAddr; // returned as the `sessionKey`/nonce field
    uint256 public expiresAt = FUTURE;
    string public userId = "sub_alice"; // immutable JWT `sub`

    function set(string memory h, address a, uint256 e) external {
        handle = h;
        nonceAddr = a;
        expiresAt = e;
        // Derive a unique id per handle so distinct identities map to
        // distinct wallets (identity keys on the id).
        userId = string(abi.encodePacked("sub_", h));
    }

    function setUserId(string memory u) external {
        userId = u;
    }

    function verifyAndExtract(bytes calldata)
        external
        view
        override
        returns (string memory, address, uint256, string memory)
    {
        return (handle, nonceAddr, expiresAt, userId);
    }

    function rotateRoots(bytes calldata) external override {}

    function platformName() external pure override returns (string memory) {
        return "stub-oidc";
    }
}

/// Dispatcher-level tests for `Registry.link_identity_oidc`. The link path
/// attaches an OIDC handle to the *calling* wallet (front-run safe: the JWT
/// nonce must equal msg.sender), instead of deploying a new wallet the way
/// `register_session_oidc` does.
contract RegistryOidcLinkFlowTest is Test {
    Registry registry;
    WalletFactory factory;
    StubOidcVerifier verifier;

    address constant OWNER = address(0xA11CE);
    address constant NOTARY = address(0xB0B);
    address constant BACKEND = address(0xBE);
    string constant PLATFORM = "www.googleapis.com";

    address wallet; // an existing registered WebWallet (the link target)

    function setUp() public {
        WebWallet walletImpl = new WebWallet();
        WalletFactory fImpl = new WalletFactory();
        factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl), abi.encodeCall(WalletFactory.initialize, (OWNER, address(walletImpl), address(1)))
                )
            )
        );

        Registry rImpl = new Registry();
        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl),
                    abi.encodeCall(
                        Registry.initialize, (address(deployNotary(OWNER, NOTARY)), BACKEND, address(factory), OWNER)
                    )
                )
            )
        );

        vm.prank(OWNER);
        factory.setRegistry(address(registry));

        verifier = new StubOidcVerifier();
        vm.prank(OWNER);
        registry.setOidcVerifier(PLATFORM, IOidcVerifier(address(verifier)));

        // Stand up an existing wallet by registering a first handle.
        verifier.set("existing@gmail.com", address(0xC0FFEE), FUTURE);
        registry.register_session_oidc(PLATFORM, hex"");
        wallet = registry.resolve(PLATFORM, "existing@gmail.com");
        assertTrue(wallet != address(0));
    }

    function test_link_happy_attachesHandleToCallingWallet() public {
        // nonce bound to the calling wallet; fresh session key for the handle.
        verifier.set("alice@gmail.com", wallet, FUTURE);
        vm.prank(wallet);
        registry.link_identity_oidc(PLATFORM, hex"", address(0xDECAF));

        assertEq(registry.resolve(PLATFORM, "alice@gmail.com"), wallet);
        // Sessions are keyed by the immutable platform id (userId), not the
        // handle (WebWallet._identityKey(platform, userId) since #111).
        assertEq(
            WebWallet(payable(wallet)).sessionAt(keccak256(abi.encode(PLATFORM, verifier.userId())), 0),
            address(0xDECAF)
        );
    }

    function test_link_walletMismatch_reverts() public {
        // nonce bound to a different address than the caller → front-run guard.
        verifier.set("alice@gmail.com", address(0xBEEF), FUTURE);
        vm.prank(wallet);
        vm.expectRevert(Registry.LinkWalletMismatch.selector);
        registry.link_identity_oidc(PLATFORM, hex"", address(0xDECAF));
    }

    function test_link_unregisteredCaller_reverts() public {
        address stranger = address(0x5727A6);
        verifier.set("alice@gmail.com", stranger, FUTURE);
        vm.prank(stranger);
        vm.expectRevert(Registry.NotRegisteredWallet.selector);
        registry.link_identity_oidc(PLATFORM, hex"", address(0xDECAF));
    }

    function test_link_idAlreadyLinkedToOtherWallet_reverts() public {
        // wallet links alice's id.
        verifier.set("alice@gmail.com", wallet, FUTURE);
        vm.prank(wallet);
        registry.link_identity_oidc(PLATFORM, hex"", address(0xDECAF));

        // Stand up a second registered wallet.
        verifier.set("second@gmail.com", address(0xBEEF11), FUTURE);
        registry.register_session_oidc(PLATFORM, hex"");
        address wallet2 = registry.resolve(PLATFORM, "second@gmail.com");
        assertTrue(wallet2 != address(0) && wallet2 != wallet);

        // wallet2 tries to link alice's id (already owned by `wallet`) → conflict.
        verifier.set("alice@gmail.com", wallet2, FUTURE);
        vm.prank(wallet2);
        vm.expectRevert(Registry.IdentityAlreadyLinked.selector);
        registry.link_identity_oidc(PLATFORM, hex"", address(0xFADE));
    }

    function test_link_unsetPlatform_reverts() public {
        verifier.set("alice@gmail.com", wallet, FUTURE);
        vm.prank(wallet);
        vm.expectRevert(Registry.OidcVerifierNotSet.selector);
        registry.link_identity_oidc("not.configured", hex"", address(0xDECAF));
    }

    function test_link_expiredJwt_reverts() public {
        vm.warp(1_000_000);
        // expiresAt + CLOCK_SKEW_GRACE <= now → JwtExpired.
        verifier.set("alice@gmail.com", wallet, 1);
        vm.prank(wallet);
        vm.expectRevert(Registry.JwtExpired.selector);
        registry.link_identity_oidc(PLATFORM, hex"", address(0xDECAF));
    }
}
