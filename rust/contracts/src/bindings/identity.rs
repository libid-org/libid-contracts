//! Bindings for the identity-names stack (`solidity/contracts/identity/`):
//! `IdentityNames`.

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
