//! Bindings for the login stack: `Registry`, `WebWallet`, `WalletFactory`,
//! `NotaryRegistry`, and the X ZK verifier. Mirrors
//! `solidity/contracts/login/`.

/// Bindings for `login/Registry.sol`.
///
/// `register_session` has many parameters by design (matching the Solidity
/// contract interface), so the too_many_arguments lint is suppressed.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod registry_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface Registry {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct FullTlsProof {
                bytes notarySignature;
                bytes backendSignature;
                address userAddress;
                address walletAddress;
                bytes32 domainHash;
                bytes32 clientRandom;
                bytes32 serverRandom;
                bytes serverEphemeralKey;
                bytes32 transcriptRoot;
                uint256 timestamp;
                bytes32[] domainPath;
                bytes32[] usernamePath;
                bytes32[] endpointPath;
                bytes32[] idPath;
            }

            function register_session(
                FullTlsProof calldata proof,
                string calldata domain,
                string calldata username,
                string calldata userId,
                string calldata endpoint
            ) external;

            /// OIDC variant — caller provides ABI-encoded `UserProof` bytes
            /// understood by the configured `IOidcVerifier` for `platform`.
            function register_session_oidc(
                string calldata platform,
                bytes calldata oidcProof
            ) external;

            function register_session_zk(
                string calldata platform,
                bytes calldata zkProof
            ) external;

            function link_identity_zk(
                string calldata platform,
                bytes calldata zkProof
            ) external;

            function link_identity_oidc(
                string calldata platform,
                bytes calldata oidcProof,
                address sessionAddr
            ) external;

            function linkIdentity(
                string calldata platform,
                string calldata handle,
                string calldata userId,
                FullTlsProof calldata proof,
                string calldata endpoint
            ) external;

            function resolve(string calldata platform, string calldata handle) external view returns (address);
            function resolveById(string calldata platform, string calldata id) external view returns (address);
            function handleHint(string calldata platform, string calldata handle) external view returns (string memory);
            function getHandles(address wallet) external view returns (string[] memory platforms, string[] memory handles);
            function getCurrentHandles(address wallet) external view returns (string[] memory platforms, string[] memory handles);
            function getUserIds(address wallet) external view returns (string[] memory platforms, string[] memory userIds);
            function getPlatform(string calldata domain) external view returns (string memory endpoint, string memory handlePrefix);
            function zkVerifierOf(string calldata domain) external view returns (address);
            function oidcVerifierOf(string calldata platform) external view returns (address);
            function notary() external view returns (address);
            function backend() external view returns (address);
            function walletFactory() external view returns (address);

            event HandleRegistered(string platform, string handle, address indexed owner);
            event SessionRegistered(string platform, string handle, address indexed wallet, address sessionAddr);
            event IdentityLinked(string platform, string handle, address indexed wallet);
            event HandleChanged(string platform, string userId, string handle);
        }
    }
}

pub use registry_inner::Registry;

/// Owner/deploy-time surface of the Registry: `initialize` (ABI-encoded into
/// the ERC1967 proxy init data) and configuration setters.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod registry_admin_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IRegistryAdmin {
            function initialize(address _notary, address _backend, address _walletFactory, address _owner) external;
            function setPlatform(
                string calldata domain,
                string calldata endpoint,
                string calldata handlePrefix,
                string calldata idPrefix,
                string calldata idSuffix
            ) external;
            function removePlatform(string calldata domain) external;
            function setZkVerifier(string calldata domain, address verifier) external;
            function setOidcVerifier(string calldata platform, address verifier) external;
            function setNotary(address _notary) external;
            function setBackend(address _backend) external;
            function pause() external;
            function unpause() external;
        }
    }
}

pub use registry_admin_inner::IRegistryAdmin;

/// Bindings for `login/zk/XZkVerifier.sol`.
///
/// The Registry calls this verifier through `IZkSessionVerifier`; a consumer
/// uses these bindings to ABI-encode `XProof` (the opaque payload it forwards
/// on `register_session_zk(platform, bytes)`) and to verify proofs via
/// `eth_call` in pre-flight.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod x_zk_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface XZkVerifier {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct TokenAttestation {
                bytes32 bearerHash;
                uint32  bearerRangeStart;
                uint32  bearerRangeEnd;
                bytes   sentRevealed;
                uint64  timestamp;
                bytes   notarySignature;
            }

            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct MeAttestation {
                bytes32 bearerHash;
                uint32  bearerRangeStart;
                uint32  bearerRangeEnd;
                bytes   sentRevealed;
                uint32  sentPrefixEnd;
                uint32  sentSuffixEnd;
                bytes   recvRevealed;
                string  handle;
                string  userId;
                address sessionAddr;
                uint64  timestamp;
                bytes   notarySignature;
            }

            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct XProof {
                bytes proof;
                bytes32[] publicInputs;
                TokenAttestation tokenAttest;
                MeAttestation meAttest;
            }

            function initialize(
                address _owner,
                address _notary,
                address _honkVerifier,
                bytes calldata _xClientId,
                string calldata _endpoint,
                string calldata _handlePrefix,
                string calldata _platformName
            ) external;

            function verifyAndExtract(bytes calldata payload)
                external view
                returns (
                    string memory handle,
                    address sessionKey,
                    address walletAddress,
                    uint256 expiresAt,
                    bytes32 nullifier,
                    string memory userId
                );

            function platformName() external view returns (string memory);
            function notary() external view returns (address);

            /// client_id allowlist. An EMPTY allowlist denies every client_id;
            /// `openClientIds` is the explicit opt-in to accept any app.
            function isClientIdAllowed(bytes32 clientIdHash) external view returns (bool);
            function openClientIds() external view returns (bool);
            function clientIdCount() external view returns (uint256);
            function clientIdAt(uint256 index) external view returns (bytes memory);

            function addClientId(bytes calldata _id) external;
            function removeClientId(bytes calldata _id) external;
            function setOpenClientIds(bool _open) external;

            event ClientIdAdded(bytes clientId);
            event ClientIdRemoved(bytes clientId);
            event OpenClientIdsSet(bool open);
        }
    }
}

pub use x_zk_verifier_inner::XZkVerifier;

/// Bindings for `login/WebWallet.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod wallet_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface WebWallet {
            function threshold() external view returns (uint8);
            function nonce() external view returns (uint256);
            function registry() external view returns (address);
            function factory() external view returns (address);
            function identityCount() external view returns (uint256);
            function identityAt(uint256 index) external view returns (bytes32);
            function isIdentity(bytes32 identityHash) external view returns (bool);
            function sessionCount(bytes32 platformHandleKey) external view returns (uint256);
            function sessionAt(bytes32 platformHandleKey, uint256 index) external view returns (address);
            function isSession(address addr) external view returns (bool);
            function sessionIdentity(address addr) external view returns (bytes32);
            function execute(
                address target,
                uint256 value,
                bytes calldata data,
                bytes[] calldata sigs
            ) external;
            function executeBatch(
                address[] calldata targets,
                uint256[] calldata values,
                bytes[] calldata datas,
                bytes[] calldata sigs
            ) external;
            function upgradeToLatest() external;
            function setThreshold(uint8 newThreshold) external;

            event SessionRegistered(string platform, string handle, address indexed sessionAddr);
            event SessionRevoked(string platform, string handle, address indexed sessionAddr);
            event Executed(address indexed target, uint256 value, uint256 nonce);
            event NativeReceived(address indexed from, uint256 amount);
            event NativeSent(address indexed to, uint256 amount);
        }
    }
}

pub use wallet_inner::WebWallet;

/// Bindings for `login/WalletFactory.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod factory_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface WalletFactory {
            function initialize(address owner_, address walletImpl_, address registry_) external;
            function setRegistry(address newRegistry) external;
            function latestImplementation() external view returns (address);
            function upgradeWalletImplementation(address newImplementation) external;

            event WalletCreated(address indexed wallet, bytes32 indexed firstIdentity);
            event WalletImplementationUpgraded(address indexed newImplementation);
        }
    }
}

pub use factory_inner::WalletFactory;

/// Bindings for `login/NotaryRegistry.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod notary_registry_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface NotaryRegistry {
            function initialize(address owner_, address initialNotary) external;
            function addNotary(address notary) external;
            function removeNotary(address notary) external;

            event NotaryAdded(address indexed notary);
            event NotaryRemoved(address indexed notary);
        }
    }
}

pub use notary_registry_inner::NotaryRegistry;

/// Minimal ERC-20 surface (transfer event scanning + balances).
#[allow(clippy::too_many_arguments, unused_attributes)]
mod erc20_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IERC20 {
            function balanceOf(address account) external view returns (uint256);
            function transfer(address to, uint256 value) external returns (bool);
            function approve(address spender, uint256 value) external returns (bool);
            function allowance(address owner, address spender) external view returns (uint256);

            event Transfer(address indexed from, address indexed to, uint256 value);
            event Approval(address indexed owner, address indexed spender, uint256 value);
        }
    }
}

pub use erc20_inner::IERC20;

/// UltraHonk verifier interface — matches the `IHonkVerifier` the login and
/// identity verifiers call. Used off-chain in pre-flight to bounce bogus proof
/// bytes before paying gas. View call only; no state mutation.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod honk_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IHonkVerifier {
            function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
        }
    }
}

pub use honk_verifier_inner::IHonkVerifier;
