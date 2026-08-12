// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Create3 — deploy to an address that depends on (deployer, salt) only.
///
/// @notice Plain CREATE2 folds the init-code hash into the address, so a new
///         implementation version or different constructor args would land at
///         a different address. CREATE3 removes the bytecode from the formula
///         entirely by adding one indirection:
///
///         1. CREATE2-deploy a tiny, CONSTANT proxy keyed by `salt`. Its
///            address is `keccak256(0xff ++ deployer ++ salt ++
///            keccak256(PROXY_INITCODE))[12:]` — a function of the deployer
///            and the salt only, because the proxy bytecode never changes.
///         2. Call that proxy with the target's creation code as raw
///            calldata; the proxy CREATE-deploys it. A fresh contract does
///            its first CREATE at nonce 1 (EIP-161), so the target lands at
///            `keccak256(rlp([proxy, 1]))[12:]` — again independent of the
///            creation code.
///
///         Net: target address = f(deployer, salt). The same salt yields the
///         same address on every chain and for every version of the target's
///         bytecode.
///
/// @dev This is the well-known solmate/CREATE3 pattern, ported here so the
///      factory has no external dependencies. The proxy's 16-byte init code
///      returns an 8-byte runtime, `36 3d 3d 37 36 3d 34 f0`:
///
///        CALLDATASIZE RETURNDATASIZE RETURNDATASIZE CALLDATACOPY   — copy
///          the whole calldata (the target's creation code) to memory 0;
///        CALLDATASIZE RETURNDATASIZE CALLVALUE CREATE              — CREATE
///          it, forwarding any callvalue.
///
///      The runtime does not return the created address (it leaves CREATE's
///      result on the stack and falls off the end), which is why the caller
///      computes the target address itself from the proxy's nonce-1 formula
///      and then verifies code actually landed there.
library Create3 {
    /// The CREATE2 proxy died (out of gas, or the same salt was already used
    /// by this deployer — the proxy address is occupied).
    error ProxyDeployFailed();

    /// The proxy ran but no code landed at the predicted address (the
    /// target's constructor reverted, or the creation code returned empty).
    error TargetDeployFailed();

    /// `PUSH8 363d3d37363d34f0; RETURNDATASIZE MSTORE; PUSH1 8; PUSH1 24;
    /// RETURN` — writes the 8 runtime bytes (right-aligned in the word at
    /// memory 0, so they start at offset 24) and returns them. MUST NEVER
    /// CHANGE: its hash is baked into every predicted address.
    bytes internal constant PROXY_INITCODE = hex"67363d3d37363d34f03d5260086018f3";

    bytes32 internal constant PROXY_INITCODE_HASH = keccak256(PROXY_INITCODE);

    /// Deploy `creationCode` at `addressOf(salt, address(this))`.
    function deploy(bytes32 salt, bytes memory creationCode) internal returns (address deployed) {
        bytes memory proxyInitcode = PROXY_INITCODE;
        address proxy;
        assembly ("memory-safe") {
            proxy := create2(0, add(proxyInitcode, 0x20), mload(proxyInitcode), salt)
        }
        if (proxy == address(0)) revert ProxyDeployFailed();

        deployed = addressOf(salt, address(this));
        (bool success,) = proxy.call(creationCode);
        if (!success || deployed.code.length == 0) revert TargetDeployFailed();
    }

    /// The address `deploy(salt, ·)` lands on when `deployer` runs it —
    /// computable before anything is deployed, on any chain.
    function addressOf(bytes32 salt, address deployer) internal pure returns (address) {
        address proxy =
            address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", deployer, salt, PROXY_INITCODE_HASH)))));
        // keccak256(rlp([proxy, 1])): 0xd6 = list of 22 bytes, 0x94 = 20-byte
        // string (the address), 0x01 = the nonce.
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
    }
}
