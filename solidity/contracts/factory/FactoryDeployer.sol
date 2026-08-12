// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {FACTORY_GENESIS_ADMIN} from "./FactoryGenesis.sol";
import {LibidFactory} from "./LibidFactory.sol";

/// @title FactoryDeployer — the frozen bootstrap material for the canonical
///        factory, and the math that predicts its address.
///
/// @notice The factory (impl AND proxy) is deployed through the canonical
///         keyless CREATE2 deployer (Arachnid's deterministic-deployment
///         proxy at `CREATE2_DEPLOYER`, present or installable on every
///         standard EVM chain), with fixed salts and FROZEN init codes:
///
///           implAddress  = CREATE2(CREATE2_DEPLOYER, IMPL_SALT,  implInitCode)
///           factoryAddr  = CREATE2(CREATE2_DEPLOYER, PROXY_SALT, proxyInitCode)
///
///         `implInitCode` is the LibidFactory creation code (no constructor
///         args). `proxyInitCode` is the ERC1967Proxy creation code with
///         `(implAddress, abi.encodeCall(initialize, (FACTORY_GENESIS_ADMIN)))`
///         appended — the impl address is itself deterministic, and the admin
///         is a baked constant, so the proxy's constructor args are
///         network-invariant. Result: `predictFactoryAddress()` is the same
///         on every EVM network, and the proxy initializes atomically inside
///         its own deployment (no front-run window).
///
/// @dev THE INIT CODES ARE FROZEN. They are pinned by the compiler settings
///      (solc 0.8.33, via_ir, 200 runs, no CBOR metadata) and by the sources;
///      `test/FactoryDeployer.t.sol` asserts the built artifacts match
///      `type(·).creationCode`, and the vendored artifacts in
///      `rust/contracts/artifacts` carry the same bytes. Changing
///      LibidFactory's source, the admin constant, or the compiler settings
///      changes the init code and therefore the canonical address — that is a
///      v2 factory and MUST use new salts (`libid.factory{,.impl}.v2`), never
///      a silent replacement of v1. Factory-behavior changes that should NOT
///      move the address go through the normal UUPS upgrade instead.
///
///      To deploy on a new network, send two transactions to
///      `CREATE2_DEPLOYER` (its calldata format is `salt ++ initCode`):
///      first `implDeployCalldata()`, then `proxyDeployCalldata()`.
///      `rust/contracts/src/factory.rs::ensure_factory` automates this,
///      including installing the CREATE2 deployer itself via its well-known
///      presigned transaction where it is missing.
library FactoryDeployer {
    /// Arachnid's deterministic-deployment proxy — deployed from a keyless
    /// one-time account, so it has this address on every chain.
    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// Fixed salt of the factory implementation. v2 = new salt.
    bytes32 internal constant IMPL_SALT = keccak256("libid.factory.impl.v1");

    /// Fixed salt of the factory proxy — the canonical factory address hangs
    /// off this one. v2 = new salt.
    bytes32 internal constant PROXY_SALT = keccak256("libid.factory.v1");

    /// The frozen implementation init code: LibidFactory's creation code,
    /// no constructor args (the constructor only calls _disableInitializers).
    function implInitCode() internal pure returns (bytes memory) {
        return type(LibidFactory).creationCode;
    }

    /// Where the implementation lands. Deterministic, but nothing points at
    /// this address except the proxy's constructor args.
    function predictImplAddress() internal pure returns (address) {
        return _create2Address(CREATE2_DEPLOYER, IMPL_SALT, keccak256(implInitCode()));
    }

    /// The frozen proxy init code: ERC1967Proxy creation code ++
    /// abi.encode(implAddress, initialize(FACTORY_GENESIS_ADMIN)). Every byte
    /// of it is network-invariant.
    function proxyInitCode() internal pure returns (bytes memory) {
        return abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(predictImplAddress(), abi.encodeCall(LibidFactory.initialize, (FACTORY_GENESIS_ADMIN)))
        );
    }

    /// The canonical factory address — the same on every EVM network.
    function predictFactoryAddress() internal pure returns (address) {
        return _create2Address(CREATE2_DEPLOYER, PROXY_SALT, keccak256(proxyInitCode()));
    }

    /// Calldata for `CREATE2_DEPLOYER` that deploys the implementation.
    function implDeployCalldata() internal pure returns (bytes memory) {
        return abi.encodePacked(IMPL_SALT, implInitCode());
    }

    /// Calldata for `CREATE2_DEPLOYER` that deploys (and atomically
    /// initializes) the factory proxy. Requires the implementation to exist
    /// already: ERC1967Proxy's constructor refuses an implementation with no
    /// code.
    function proxyDeployCalldata() internal pure returns (bytes memory) {
        return abi.encodePacked(PROXY_SALT, proxyInitCode());
    }

    function _create2Address(address deployer, bytes32 salt, bytes32 initCodeHash) private pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", deployer, salt, initCodeHash)))));
    }
}
