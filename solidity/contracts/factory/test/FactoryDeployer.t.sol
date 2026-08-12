// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {FACTORY_GENESIS_ADMIN} from "../FactoryGenesis.sol";
import {FactoryDeployer} from "../FactoryDeployer.sol";
import {LibidFactory} from "../LibidFactory.sol";
import {Ping} from "./Create3.t.sol";

/// The canonical bootstrap path, simulated: Arachnid's deterministic-
/// deployment proxy is etched at its well-known address (its runtime bytecode
/// is fixed — every chain that has it has these exact bytes), then the frozen
/// impl and proxy init codes are deployed through it exactly as
/// `ensure_factory` does on a real network.
contract FactoryDeployerTest is Test {
    /// The runtime bytecode of the deterministic-deployment proxy — the code
    /// that lives at 0x4e59b4…956C on every chain it was installed on.
    /// Calldata format: 32-byte salt ++ init code; returns the 20-byte
    /// deployed address.
    bytes internal constant ARACHNID_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    function setUp() public {
        vm.etch(FactoryDeployer.CREATE2_DEPLOYER, ARACHNID_RUNTIME);
    }

    function _deployVia(bytes memory data) internal returns (bool ok, address addr) {
        bytes memory ret;
        (ok, ret) = FactoryDeployer.CREATE2_DEPLOYER.call(data);
        if (ok && ret.length == 20) {
            addr = address(bytes20(ret));
        }
    }

    function _bootstrap() internal returns (address impl, address factoryAddr) {
        bool ok;
        (ok, impl) = _deployVia(FactoryDeployer.implDeployCalldata());
        assertTrue(ok, "impl deploy failed");
        (ok, factoryAddr) = _deployVia(FactoryDeployer.proxyDeployCalldata());
        assertTrue(ok, "proxy deploy failed");
    }

    function test_bootstrap_landsOnThePredictedAddresses() public {
        (address impl, address factoryAddr) = _bootstrap();
        assertEq(impl, FactoryDeployer.predictImplAddress());
        assertEq(factoryAddr, FactoryDeployer.predictFactoryAddress());
        assertGt(impl.code.length, 0);
        assertGt(factoryAddr.code.length, 0);
    }

    /// The anti-front-running property: the instant the proxy exists, it is
    /// already initialized with the baked genesis admin. There is no
    /// deploy-then-initialize gap.
    function test_bootstrap_ownerIsTheGenesisAdminAtomically() public {
        (, address factoryAddr) = _bootstrap();
        LibidFactory factory = LibidFactory(factoryAddr);
        assertEq(factory.owner(), FACTORY_GENESIS_ADMIN);

        // Nobody can re-initialize the proxy…
        vm.expectRevert();
        factory.initialize(address(this));
    }

    /// …and the raw implementation is bricked by _disableInitializers.
    function test_bootstrap_rawImplementationCannotBeInitialized() public {
        (address impl,) = _bootstrap();
        vm.expectRevert();
        LibidFactory(impl).initialize(address(this));
    }

    /// ERC1967Proxy's constructor refuses an implementation with no code, so
    /// the proxy cannot be deployed ahead of the impl (wrong order fails
    /// loudly instead of minting a broken factory).
    function test_bootstrap_proxyBeforeImplFails() public {
        (bool ok,) = _deployVia(FactoryDeployer.proxyDeployCalldata());
        assertFalse(ok);
    }

    function test_bootstrap_thenTheFactoryDeploys() public {
        (, address factoryAddr) = _bootstrap();
        LibidFactory factory = LibidFactory(factoryAddr);

        address predicted = factory.predict("libid.thing");
        vm.prank(FACTORY_GENESIS_ADMIN);
        assertEq(factory.deploy("libid.thing", type(Ping).creationCode), predicted);

        vm.prank(address(this)); // not the admin
        vm.expectRevert();
        factory.deploy("libid.other", type(Ping).creationCode);
    }

    /// The frozen init codes are exactly what forge wrote to out/ — which is
    /// exactly what scripts/vendor-artifacts.sh vendors for the Rust
    /// bootstrap (`ensure_factory`). If this breaks, the Solidity and Rust
    /// predictions have diverged.
    function test_frozenInitCode_matchesTheBuiltArtifacts() public view {
        bytes memory implArtifact =
            vm.parseJsonBytes(vm.readFile("out/LibidFactory.sol/LibidFactory.json"), ".bytecode.object");
        assertEq(keccak256(implArtifact), keccak256(FactoryDeployer.implInitCode()));

        bytes memory proxyArtifact =
            vm.parseJsonBytes(vm.readFile("out/ERC1967Proxy.sol/ERC1967Proxy.json"), ".bytecode.object");
        bytes memory expectedProxyInitCode = abi.encodePacked(
            proxyArtifact,
            abi.encode(
                FactoryDeployer.predictImplAddress(), abi.encodeCall(LibidFactory.initialize, (FACTORY_GENESIS_ADMIN))
            )
        );
        assertEq(keccak256(expectedProxyInitCode), keccak256(FactoryDeployer.proxyInitCode()));
    }
}
