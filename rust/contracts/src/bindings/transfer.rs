//! Bindings for the Bank diamond (`solidity/contracts/transfer/`): the full
//! `IBank` surface addressed through the diamond, plus the EIP-2535 cut/loupe
//! interfaces and the one-shot `BankInit`.

/// The Bank diamond's external surface (Vault + Admin + Transfer facets), for
/// callers that address the diamond as one contract. Mirrors
/// `transfer/bank/IBank.sol` and the facet sources.
///
/// `balanceOf` and `balanceOfTotal` are overloaded exactly as in Solidity;
/// alloy disambiguates the generated Rust methods as `balanceOf_0`
/// (address-keyed) and `balanceOf_1` (identity-keyed), in declaration order.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod bank_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface Bank {
            struct NotaryTlsProof {
                bytes notarySig;
                bytes32 domainHash;
                bytes32 clientRandom;
                bytes32 serverRandom;
                bytes serverEphemeralKey;
                bytes32 transcriptRoot;
                uint256 timestamp;
                bytes32[] bodyMerklePath;
                bytes32[] authorMerklePath;
                bytes32[] domainMerklePath;
                bytes32[] endpointMerklePath;
                bytes32[] authorIdMerklePath;
                bytes32[] receiverIdMerklePath;
                bytes revealedReceiverId;
                bytes32[] quotedRefMerklePath;
                bytes revealedQuotedRef;
                bytes32[] quotedAuthorMerklePath;
                bytes revealedQuotedAuthorId;
            }

            struct ResourceInfo {
                string platform;      // API domain (e.g. "api.x.com")
                string resourceType;
                string resourceId;
                string requestPath;
            }

            struct SenderInfo {
                string author;
                bytes revealedAuthor;
                bytes revealedAuthorId;
            }

            struct BackendSig {
                bytes sig;
                uint256 timestamp;
            }

            // ── Transfer facet ───────────────────────────────────────────

            /// Token-by-name overload.
            function webTransferV2(
                ResourceInfo calldata resource,
                SenderInfo calldata sender,
                bytes calldata revealedSubsection,
                NotaryTlsProof calldata notaryTlsProof,
                BackendSig calldata backendSigData,
                string calldata receiverHandle,
                string calldata receiverUserId,
                string calldata tokenName_,
                string calldata amountStr,
                uint256 amount,
                string calldata sourceUrl
            ) external;

            /// Token-by-address overload.
            function webTransferV2(
                ResourceInfo calldata resource,
                SenderInfo calldata sender,
                bytes calldata revealedSubsection,
                NotaryTlsProof calldata notaryTlsProof,
                BackendSig calldata backendSigData,
                string calldata receiverHandle,
                string calldata receiverUserId,
                address token,
                string calldata amountStr,
                uint256 amount,
                string calldata sourceUrl
            ) external;

            /// Stateless preflight of a TLS-notarized comment proof.
            function verifyProof(
                ResourceInfo calldata resource,
                SenderInfo calldata sender,
                bytes calldata revealedSubsection,
                NotaryTlsProof calldata notaryTlsProof,
                BackendSig calldata backendSigData,
                string calldata receiverUserId
            ) external view returns (bool);

            function transfer_within(
                string calldata receiverPlatform,
                string calldata receiverHandle,
                string calldata receiverUserId,
                address token,
                uint256 amount
            ) external;

            // ── Vault facet ──────────────────────────────────────────────

            function deposit(string calldata platform, string calldata handle, string calldata userId, address token, uint256 amount) external payable;
            function withdraw(address recipient, address token, uint256 amount) external;
            function balanceOf(address wallet, address token) external view returns (uint256);
            function balanceOf(string calldata platform, string calldata handle, string calldata userId, address token) external view returns (uint256);
            function balanceOfTotal(address wallet, address token) external view returns (uint256);
            function balanceOfTotal(string calldata platform, string calldata handle, string calldata userId, address token) external view returns (uint256);
            function registeredBalances(address wallet, address token) external view returns (uint256);
            function unregisteredBalances(bytes32 key, address token) external view returns (uint256);
            function identityHash(string calldata domain, string calldata username) external pure returns (bytes32);

            // ── Admin facet ──────────────────────────────────────────────

            function pause() external;
            function unpause() external;
            function setRegistry(address _registry) external;
            function registerToken(string calldata name, address token) external;
            function unregisterToken(string calldata name) external;
            function resolveToken(string calldata name) external view returns (address);
            function getRegisteredTokens() external view returns (address[] memory);
            function tokenName(address token) external view returns (string memory);
            function setPlatformTemplate(string calldata platform, string calldata newTemplate) external;
            function clearPlatformTemplates(string calldata platform) external;
            function platformTemplateCount(string calldata platform) external view returns (uint256);
            function getPlatformTemplate(string calldata platform, uint256 index) external view returns (string memory);
            function setResourceTypePrefix(string calldata resourceType, string calldata prefix) external;
            function setPlatformWebPrefix(string calldata platform, string calldata prefix) external;
            function getPlatformWebPrefix(string calldata platform) external view returns (string memory);
            function registry() external view returns (address);
            function paused() external view returns (bool);

            // ── Events ───────────────────────────────────────────────────

            event Deposited(address indexed wallet, bytes32 indexed handleKey, address indexed token, uint256 amount);
            event Withdrawn(address indexed wallet, address indexed recipient, address indexed token, uint256 amount);
            event TransferWithin(address indexed sender, string receiverPlatform, string receiverHandle, string receiverUserId, address indexed token, uint256 amount);
            event WebTransferV3(address indexed senderWallet, address indexed receiverWallet, string receiverPlatform, string receiverHandle, string receiverUserId, address indexed token, uint256 amount, string sourceUrl);
            event Paused(address account);
            event Unpaused(address account);
            event RegistrySet(address indexed oldRegistry, address indexed newRegistry);
            event TokenRegistered(string name, address indexed token);
            event TokenUnregistered(string name, address indexed token);
        }
    }
}

pub use bank_inner::Bank;

/// EIP-2535 diamond cut interface (`transfer/diamond/interfaces/IDiamondCut.sol`).
#[allow(clippy::too_many_arguments, unused_attributes)]
mod diamond_cut_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IDiamondCut {
            /// `action` is FacetCutAction as its ABI underlying type (0=Add,
            /// 1=Replace, 2=Remove); enums encode as uint8, so this yields the
            /// same `diamondCut` selector as the Solidity interface.
            struct FacetCut {
                address facetAddress;
                uint8 action;
                bytes4[] functionSelectors;
            }
            function diamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata) external;

            event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata);
        }
    }
}

pub use diamond_cut_inner::IDiamondCut;

/// EIP-2535 loupe + ERC-173 ownership
/// (`transfer/diamond/interfaces/IDiamondLoupe.sol`, `IERC173.sol`).
#[allow(clippy::too_many_arguments, unused_attributes)]
mod diamond_loupe_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IDiamondLoupe {
            struct Facet {
                address facetAddress;
                bytes4[] functionSelectors;
            }
            function facets() external view returns (Facet[] memory facets_);
            function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory);
            function facetAddresses() external view returns (address[] memory);
            function facetAddress(bytes4 _functionSelector) external view returns (address);
            function supportsInterface(bytes4 _interfaceId) external view returns (bool);
        }
    }

    sol! {
        #[sol(rpc)]
        interface IERC173 {
            function owner() external view returns (address owner_);
            function transferOwnership(address _newOwner) external;
        }
    }
}

pub use diamond_loupe_inner::{
    IDiamondLoupe,
    IERC173,
};

/// One-shot diamond initializer (`transfer/bank/BankInit.sol`). No
/// `#[sol(rpc)]`: only `initCall` is used — ABI-encoded as the diamondCut
/// `_init` delegatecall calldata that runs BankInit in the diamond's storage.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod bank_init_inner {
    use alloy::sol;

    sol! {
        interface BankInit {
            function init(address notary, address backend, address registry) external;
        }
    }
}

pub use bank_init_inner::BankInit;
