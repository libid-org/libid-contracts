//! Bindings for the ceremony verification path (`solidity/contracts/ceremony/`):
//! the Notary Service every notarized session is authenticated through, the
//! Proof Verifier that routes a claim to the Platform Verifier registered for
//! its version, and the Google JWT root list the `google/v1` verifier reads.

/// Bindings for `ceremony/NotaryService.sol` (which implements
/// `INotaryService`).
///
/// Authenticates one attestation and charges one fee for it. The digest is
/// derived from the attested bytes on chain, never taken from the caller
/// (REQ-COMMON-49), which is why `verify` is not on this interface: a
/// consumer contract calls it with the fee attached, and the decoded record
/// comes back to that contract, not to an off-chain reader. What an operator
/// does from here is hold the trusted key set, set the fee and withdraw what
/// accrued.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod notary_service_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface NotaryService {
            /// `notary_` is the first trusted key; `fee_` may be zero (a
            /// deployment may meter at no charge, and the exact-value rule
            /// still applies).
            function initialize(address owner_, address notary_, uint256 fee_) external;
            /// What one verification costs, in the chain's native asset.
            /// Readable before a submission is built, so it can be bounded.
            function fee() external view returns (uint256);
            function setFee(uint256 fee_) external;
            /// Add or remove a trusted notary key. Several are held at once so
            /// a rotation can overlap: add the incoming key, remove the
            /// outgoing one once nothing can still present under it.
            function setNotary(address key, bool trusted_) external;
            function isTrustedNotary(address key) external view returns (bool);
            /// Fees accrue here rather than being forwarded per verification.
            function withdraw(address to, uint256 amount) external;

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event FeeChanged(uint256 previousFee, uint256 newFee);
            event NotaryTrustChanged(address indexed key, bool trusted);
            event FeesWithdrawn(address indexed to, uint256 amount);
        }
    }
}

pub use notary_service_inner::NotaryService;

/// Bindings for `ceremony/CeremonyProofVerifier.sol` (which implements
/// `IProofVerifier`).
///
/// The Supported Version Set: which Platform Verifier answers for a
/// `(platformId, verifierVersion)` pair. Governance registers one with
/// `setVerifier`; `IdentityNames.claim` dispatches through `verify`, which is
/// not on this interface for the same reason `NotaryService.verify` is not —
/// it is called by the consumer contract with the fee attached.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod proof_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface CeremonyProofVerifier {
            function initialize(address owner_) external;
            /// Register (or, with the zero address, remove) the Platform
            /// Verifier for a pair. The verifier must serve `platformId`.
            function setVerifier(bytes32 platformId, uint16 verifierVersion, address verifier) external;
            /// The Platform Verifier registered for a pair, or zero.
            function verifierOf(bytes32 platformId, uint16 verifierVersion) external view returns (address);
            /// What one claim under this pair costs: the registered
            /// verifier's quote, forwarded whole.
            function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
            /// Whether any version is registered for the platform at all.
            function verifiesPlatform(bytes32 platformId) external view returns (bool);
            /// This chain's identifier, as the digest construction takes it.
            function chainId() external view returns (bytes32);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event VerifierConfigured(bytes32 indexed platformId, uint16 indexed verifierVersion, address verifier);
        }
    }
}

pub use proof_verifier_inner::CeremonyProofVerifier;

/// Bindings for `ceremony/GoogleJwtRoots.sol` — the signing keys the
/// `google/v1` Platform Verifier trusts, and until when. Starts EMPTY:
/// Google names bind only once a notarized reading of Google's JWKS has
/// landed here.
///
/// A rotation is an ordinary notarized session: the keeper reveals the whole
/// `GET /oauth2/v3/certs` exchange, `rotate` hands the attested bytes and the
/// notary's proof to the Notary Service with the Notary Fee attached (read
/// it with `quoteRotation`, which is the service's `fee()`), and the contract
/// reads the JWKS out of the transcript it vouched for.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod google_jwt_roots_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface GoogleJwtRoots {
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

pub use google_jwt_roots_inner::GoogleJwtRoots;
