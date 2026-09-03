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
/// The list is two generations of Google's key set and nothing else:
/// `current` is the latest reading applied, `previous` the reading before
/// it, kept for the tokens still in flight under a key Google has since
/// dropped. A newer reading of the same set restarts `current`'s clock
/// (`ReadingRefreshed`); a newer reading of a different set shifts `current`
/// into `previous` and drops what `previous` held (`KeysRotated`). A
/// generation is trusted until `READING_LIFETIME` after its reading's own
/// `createdAt`, so there is nothing to prune or untrust by hand.
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
            /// One reading of Google's key set: the notary's clock, and the
            /// limb hash of every modulus it listed, in Google's order.
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct Generation {
                uint64 observedAt;
                bytes32[] moduli;
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
            /// authentication of it (a 65-byte EIP-191 signature today). A
            /// reading dated no later than the current generation is
            /// ignored, not refused.
            function rotate(bytes calldata attestedData, bytes calldata proof) external payable;

            /// What `GooglePlatformVerifier` reads: modulus hash -> when it
            /// stops being trusted, zero when neither generation lists it.
            function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);
            /// Both generations, as stored.
            function currentKeys() external view returns (Generation memory current, Generation memory previous);
            /// The current generation's `observedAt`: the notary's clock on
            /// the reading in force.
            function freshestObservedAt() external view returns (uint256);
            /// True until the current generation is guaranteed trusted
            /// `RENEWAL_MARGIN` from now; true on an empty list.
            function needsRotation() external view returns (bool);
            function READING_LIFETIME() external view returns (uint256);
            function RENEWAL_MARGIN() external view returns (uint256);
            function MAX_KEYS() external view returns (uint256);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event NotaryServiceChanged(address notary);
            /// A different set landed: `kids` and `moduli` in the order
            /// Google listed them, `observedAt` the notary's clock.
            event KeysRotated(uint64 observedAt, string[] kids, bytes32[] moduli);
            /// A newer reading of the set already current.
            event ReadingRefreshed(uint64 observedAt);
        }
    }
}

pub use google_jwt_roots_inner::GoogleJwtRoots;
