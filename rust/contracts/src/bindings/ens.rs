//! Bindings for the ENS resolver (`solidity/contracts/ens/`).

/// Bindings for `ens/HandleResolver.sol` — the wildcard resolver for
/// `handles.link`.
///
/// Not a proxy: the owner, the gateway endpoints and the signer set arrive in
/// the constructor, and replacing the contract is `setResolver` on the ENS
/// name. Deploy it with `deploy_with_ctor` and the ABI-encoded constructor
/// tuple; `resolve` is absent because it always reverts `OffchainLookup` —
/// the client-side protocol, not something a Rust consumer calls.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        contract HandleResolver {
            constructor(address owner_, string[] memory urls_, address[] memory signers_);

            function urls(uint256 index) external view returns (string memory);
            function urlCount() external view returns (uint256);
            function signers(address signer) external view returns (bool);
            function MAX_LIFETIME() external view returns (uint256);
            function makeSignatureHash(address target, uint64 expires, bytes memory request, bytes memory result) external pure returns (bytes32);
            function resolveWithProof(bytes calldata response, bytes calldata extraData) external view returns (bytes memory);
            function supportsInterface(bytes4 interfaceId) external pure returns (bool);

            function setUrls(string[] calldata urls_) external;
            function setSigner(address signer, bool trusted) external;

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event UrlsChanged(string[] urls);
            event SignerChanged(address indexed signer, bool trusted);
        }
    }
}

pub use inner::HandleResolver;
