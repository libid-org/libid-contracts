//! Bindings for the deterministic deployment factory. Mirrors
//! `solidity/contracts/factory/`.

/// Bindings for `factory/LibidFactory.sol`.
///
/// Every protocol proxy is deployed through this factory via CREATE3 with
/// `salt = keccak256(bytes(name))`, so its address is a function of
/// (factory address, name) only — and since the factory lives at the same
/// address on every chain (see [`crate::factory`]), `predict(name)` answers
/// the same address on every EVM network.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod factory_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface LibidFactory {
            function initialize(address owner_) external;
            /// CREATE3-deploy `creationCode` under `name`; lands on
            /// `predict(name)` whatever the code is. Owner-gated; a name is
            /// single-use.
            function deploy(string calldata name, bytes calldata creationCode) external returns (address);
            /// The address `deploy(name, ·)` lands on — answerable pre-deploy.
            function predict(string calldata name) external view returns (address);
            /// Where `name` was deployed, or zero if it wasn't yet.
            function deployedAt(string calldata name) external view returns (address);
            /// Name-hash (`keccak256(bytes(name))`) → deployed address.
            function deployments(bytes32 nameHash) external view returns (address);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event Deployed(bytes32 indexed nameHash, string name, address addr);
        }
    }
}

pub use factory_inner::LibidFactory;
