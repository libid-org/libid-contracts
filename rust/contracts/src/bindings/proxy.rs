//! Proxy plumbing shared by every stack: the ERC1967 proxy constructor and
//! the UUPS upgrade entrypoint.

#[allow(clippy::too_many_arguments, unused_attributes)]
mod inner {
    use alloy::sol;

    sol! {
        /// OpenZeppelin `ERC1967Proxy` — deployed with the implementation
        /// address and the ABI-encoded initializer calldata.
        #[sol(rpc)]
        contract ERC1967Proxy {
            constructor(address implementation, bytes memory _data);
        }
    }

    sol! {
        /// The UUPS upgrade surface every proxied contract here exposes.
        #[sol(rpc)]
        interface IUUPSUpgradeable {
            function upgradeToAndCall(address newImplementation, bytes calldata data) external;
        }
    }
}

pub use inner::{
    ERC1967Proxy,
    IUUPSUpgradeable,
};
