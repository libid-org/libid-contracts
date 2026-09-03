//! Bindings for the identity-names stack (`solidity/contracts/identity/`):
//! `IdentityNames` and its Google JWKS trust list.

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

            /// The keyspace half: what a handle on this platform means. It
            /// does not vary by proof version — two versions normalizing
            /// differently would put one handle on two nodes.
            function setPlatform(bytes32 platformId, Rules calldata rules) external;

            /// Which contract holds the Supported Version Set. Registering a
            /// version is that contract's call, not this one's.
            function setProofVerifier(address verifier) external;
            function proofVerifier() external view returns (address);

            /// The one write. The contract does not know what `payload` is:
            /// it names a platform and this chain's verifier version for it,
            /// and the Proof Verifier routes the bytes to the one contract
            /// that decodes them. The value attached must equal `quoteClaim`
            /// for the same pair exactly.
            function claim(bytes32 platformId, uint16 verifierVersion, bytes calldata payload, bool publishName) external payable;
            function quoteClaim(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
            function digestSpent(bytes32 digest) external view returns (bool);
            function unpublish(bytes32 platformId) external;
            function resolveId(bytes32 platformId, string calldata userId) external view returns (address);
            function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address);
            function resolvePair(bytes32 platformId, string calldata handle, string calldata userId) external view returns (address);
            function reverseOf(address wallet, bytes32 platformId) external view returns (string memory);
            function primaryOf(address wallet, bytes32 platformId) external view returns (string memory);

            /// Carries the ceremony version that proved the binding -- logged,
            /// never stored, because nothing on chain acts on it and an
            /// operator asking which bindings a version touched reads the log.
            /// What the ceremony authenticated beyond the binding rides on
            /// `CeremonyBound` instead.
            event IdentityBound(
                address indexed owner,
                bytes32 indexed idNode,
                bytes32 indexed handleNode,
                bytes32 platformId,
                string userId,
                string handle,
                uint64 observedAt,
                bool published,
                uint16 ceremonyVersion
            );
            event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed owner);
            event PlatformConfigured(bytes32 indexed platformId);
            event ProofVerifierConfigured(address verifier);
            event NameUnpublished(address indexed owner, bytes32 indexed platformId);
            /// The OAuth client a ceremony authenticated. Nothing stores it, so
            /// "which application produced these bindings" is answerable only
            /// from this log.
            event CeremonyBound(
                bytes32 indexed authorizationDigest,
                address indexed owner,
                bytes32 indexed platformId,
                bytes clientIdentifier
            );
        }
    }
}

pub use names_inner::IdentityNames;

/// Bindings for `identity/IdentityJwksRoots.sol` — the naming system's own
/// Google JWKS trust list. Starts EMPTY: Google names bind only once a
/// notarized reading of Google's JWKS has landed here.
///
/// A rotation is an ordinary notarized session: the keeper reveals the whole
/// `GET /oauth2/v3/certs` exchange, `rotate` hands the attested bytes and the
/// notary's proof to the Notary Service with the Notary Fee attached (read
/// it with `quoteRotation`, which is the service's `fee()`), and the contract
/// reads the JWKS out of the transcript it vouched for.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod jwks_roots_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IdentityJwksRoots {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct RootInfo {
                bytes32 kidHash;
                bytes32 modulusHash;
                uint256 observedAt;
                uint256 expiresAt;
            }

            function initialize(address owner_, address notary_) external;
            /// The Notary Service a rotation is verified through.
            function notaryService() external view returns (address);
            function setNotaryService(address notary_) external;
            /// What one rotation costs beyond gas: the Notary Fee, forwarded
            /// whole. `rotate` must be sent with exactly this value.
            function quoteRotation() external view returns (uint256);
            /// Permissionless. `attestedData` is the ceremony-common section
            /// 9.1 record of the JWKS session, `proof` the notary's
            /// authentication of it (a 65-byte EIP-191 signature today).
            function rotate(bytes calldata attestedData, bytes calldata proof) external payable;
            function untrustModulus(bytes32 modulusHash) external;
            function prune() external;

            function modulusOfKid(bytes32 kidHash) external view returns (bytes32);
            function expiresAtKid(bytes32 kidHash) external view returns (uint256);
            /// What `GooglePlatformVerifier` reads: modulus hash -> expiry,
            /// zero when untrusted.
            function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);
            function rotatedAtKid(bytes32 kidHash) external view returns (uint256);
            function freshestObservedAt() external view returns (uint256);
            function currentRoots() external view returns (RootInfo[] memory);
            function needsRotation() external view returns (bool);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event NotaryServiceChanged(address notary);
            event ModulusRotated(bytes32 indexed kidHash, string kid, bytes32 modulusHash, uint256 expiresAt);
            event ModulusUntrusted(bytes32 indexed modulusHash);
            event RootApplied(bytes32 indexed kidHash, bytes32 indexed modulusHash, uint256 observedAt, uint256 expiresAt);
            event RootPruned(bytes32 indexed kidHash, bytes32 modulusHash);
        }
    }
}

pub use jwks_roots_inner::IdentityJwksRoots;
