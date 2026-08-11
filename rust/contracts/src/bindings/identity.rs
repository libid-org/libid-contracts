//! Bindings for the identity-names stack (`solidity/contracts/identity/`):
//! `IdentityNames`, the per-platform verifiers, and the Google JWKS trust
//! list.

/// Bindings for `identity/IdentityNames.sol`.
///
/// `Rules` mirrors `HandleNormalizer.Rules` — the normalization rules the
/// contract stores per platform. Platform ids are `keccak256` of the
/// platform's domain string.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod names_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IdentityNames {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct Rules {
                uint16 maxLength;
                bool stripLeadingAt;
                bool isEmail;
                bool allowUnderscore;
                bool allowHyphen;
            }

            function initialize(address owner_) external;
            function setPlatform(
                bytes32 platformId,
                address verifier,
                uint64 maxFutureObservation,
                Rules calldata rules
            ) external;

            function verifierOf(bytes32 platformId) external view returns (address);
            function bind(bytes32 platformId, bytes calldata proof, bool publishName) external;
            function unpublish(bytes32 platformId) external;
            function resolveId(bytes32 platformId, string calldata userId) external view returns (address);
            function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address);
            function resolvePair(bytes32 platformId, string calldata handle, string calldata userId) external view returns (address);
            function reverseOf(address wallet, bytes32 platformId) external view returns (string memory);
            function primaryOf(address wallet, bytes32 platformId) external view returns (string memory);

            event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed owner);
            event PlatformConfigured(bytes32 indexed platformId, address verifier);
            event NameUnpublished(address indexed owner, bytes32 indexed platformId);
        }
    }
}

pub use names_inner::IdentityNames;

/// The claim every identity verifier returns
/// (`identity/IIdentityVerifier.sol`).
#[allow(clippy::too_many_arguments, unused_attributes)]
mod verifier_iface_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IIdentityVerifier {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct IdentityClaim {
                string userId;
                string handle;
                address target;
                uint64 observedAt;
            }

            function verify(bytes calldata proof) external view returns (IdentityClaim memory claim);
            function platformName() external view returns (string memory);
        }
    }
}

pub use verifier_iface_inner::IIdentityVerifier;

/// Bindings for `identity/XIdentityVerifier.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod x_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface XIdentityVerifier {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct MeAttestation {
                bytes32 bearerHash;
                uint32 bearerRangeStart;
                uint32 bearerRangeEnd;
                bytes sentRevealed;
                uint32 sentPrefixEnd;
                uint32 sentSuffixEnd;
                bytes recvRevealed;
                string handle;
                string userId;
                address sessionAddr;
                uint64 timestamp;
                bytes notarySignature;
            }

            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct XProof {
                bytes proof;
                bytes32[] publicInputs;
                MeAttestation meAttest;
            }

            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct ResponseShape {
                string platformName;
                string endpoint;
                string handlePrefix;
                string idPrefix;
                string idSuffix;
            }

            function initialize(
                address owner_,
                address notary_,
                address honkVerifier_,
                ResponseShape calldata shape_
            ) external;
            function setTrust(address notary_, address honkVerifier_) external;
            function setResponseShape(ResponseShape calldata shape_) external;

            function platformName() external view returns (string memory);
            function endpoint() external view returns (string memory);
            function handlePrefix() external view returns (string memory);
            function idPrefix() external view returns (string memory);
            function idSuffix() external view returns (string memory);
        }
    }
}

pub use x_verifier_inner::XIdentityVerifier;

/// Bindings for `identity/GitHubIdentityVerifier.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod github_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface GitHubIdentityVerifier {
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

            /// The proof plus the strings it is checked against. A verifier
            /// takes one `bytes` argument, so they travel together.
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct GitHubProof {
                FullTlsProof tls;
                string domain;
                string handle;
                string userId;
                string endpoint;
            }

            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct ResponseShape {
                string endpoint;
                string handlePrefix;
                string idPrefix;
                string idSuffix;
            }

            function initialize(
                address owner_,
                address notary_,
                address backend_,
                ResponseShape calldata shape_
            ) external;
            function setSigners(address notary_, address backend_) external;
            function setResponseShape(ResponseShape calldata shape_) external;

            function notary() external view returns (address);
            function backend() external view returns (address);
            function platformName() external view returns (string memory);
        }
    }
}

pub use github_verifier_inner::GitHubIdentityVerifier;

/// Bindings for `identity/GoogleIdentityVerifier.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod google_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface GoogleIdentityVerifier {
            /// One proof over a Google-signed id_token. Identity binds on
            /// `sub` (the immutable Google account id).
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct UserProof {
                bytes honkProof;
                bytes32[] publicInputs;
                string email;
                address sessionKey;
                string sub;
            }

            function initialize(address owner_, address honkVerifier_, address jwksRoots_) external;
            function setTrust(address honkVerifier_, address jwksRoots_) external;

            function honkVerifier() external view returns (address);
            function jwksRoots() external view returns (address);
            function platformName() external view returns (string memory);
        }
    }
}

pub use google_verifier_inner::GoogleIdentityVerifier;

/// Bindings for `identity/IdentityJwksRoots.sol` — the naming system's own
/// Google JWKS trust list. Starts EMPTY: Google names bind only once a
/// notarized reading of Google's JWKS has landed here.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod jwks_roots_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IdentityJwksRoots {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct NotarizedJwksProof {
                bytes notarySignature;
                bytes32 domainHash;
                bytes32 clientRandom;
                bytes32 serverRandom;
                bytes serverEphemeralKey;
                bytes32 transcriptRoot;
                uint256 timestamp;
                bytes32[] domainPath;
                bytes32[] endpointPath;
            }

            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct JwkClaim {
                bytes jwkBytes;
                bytes32[] jwkPath;
                bytes kid;
                bytes nB64url;
            }

            function initialize(address owner_, address initialNotary) external;
            function addNotary(address n) external;
            function removeNotary(address n) external;
            function untrustModulus(bytes32 modulusHash) external;
            function rotate(NotarizedJwksProof calldata proof, JwkClaim[] calldata claims) external;
            function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);

            event ModulusRotated(bytes32 indexed kidHash, string kid, bytes32 modulusHash, uint256 expiresAt);
            event NotaryAdded(address indexed notary);
            event NotaryRemoved(address indexed notary);
            event ModulusUntrusted(bytes32 indexed modulusHash);
        }
    }
}

pub use jwks_roots_inner::IdentityJwksRoots;
