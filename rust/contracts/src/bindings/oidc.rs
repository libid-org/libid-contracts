//! Bindings for the Google OIDC verifier
//! (`solidity/contracts/login/oidc/GoogleOidcVerifier.sol`).

/// The surface a deployer and a JWKS rotation listener need. Keep the struct
/// fields in lockstep with the Solidity types.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface GoogleOidcVerifier {
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

            /// `_verifier` is the deployed Honk circuit verifier
            /// (`Verifier.sol:HonkVerifier`); `notaryContract_` is the shared
            /// Notary contract; `initialAud` seeds the audience allowlist —
            /// without it the verifier is fail-closed and rejects every proof.
            function initialize(
                address _verifier,
                address _owner,
                address notaryContract_,
                string calldata initialAud
            ) external;

            function setExpectedAudience(string calldata clientId) external;
            function setExpectedAudienceHash(bytes32 audienceHash) external;
            function setRegistry(address r) external;

            function modulusOfKid(bytes32 kidHash) external view returns (bytes32);
            function expiresAtKid(bytes32 kidHash) external view returns (uint256);
            function platformName() external view returns (string memory);
            function notaryContract() external view returns (address);
            function notary() external view returns (address);

            function rotate(NotarizedJwksProof calldata proof, JwkClaim[] calldata claims) external;

            event ModulusRotated(bytes32 indexed kidHash, string kid, bytes32 modulusHash, uint256 expiresAt);
            event AudienceConfigured(bytes32 indexed audienceHash, string clientId);
        }
    }
}

pub use inner::GoogleOidcVerifier;
