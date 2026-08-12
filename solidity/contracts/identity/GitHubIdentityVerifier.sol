// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {IdentityClaim, IIdentityVerifier} from "./IIdentityVerifier.sol";
import {INotary} from "../notary/INotary.sol";

/// @title GitHubIdentityVerifier - the naming system's own GitHub proof.
///
/// @notice Verifies a notarized TLS session of GitHub's `/user` and returns the
///         account it names.
///
/// @dev **This contract is the one the notary attests to.** The digest binds
///      `address(this)`, so a signature made out to any other contract does not
///      recover here — and the naming system's notary is its own deployment,
///      configured with this address. It reads nothing from the wallet product
///      and shares no contract with it.
///
///      That is a duplicate of the wallet product's proof pipeline, on purpose.
///      The two happen to speak the same protocol to the same API today, and
///      reusing one for the other would tie a naming release to a wallet
///      release, put a wallet contract's address inside a name binding, and
///      leave the naming system undeployable by anyone who does not run the
///      wallet. A duplicated pipeline costs a second attestation; a shared one
///      costs the independence the naming system is for.
///
///      **The notary is the only trust root here**, as it is for X and Google.
///
///      **`walletAddress` is NOT authenticated.** The notary digest does not
///      cover it, so a proof can be re-pointed at any address and still verifies.
///      `verify` is a view and proofs arrive as public calldata, so a successful
///      claim can be copied out of a block, its wallet swapped, and resubmitted by
///      the attacker to satisfy `IdentityNames`' `msg.sender` check.
///
///      Closing it belongs in the proof and needs no new machinery: the notary
///      commits the request path as an `endpoint:` leaf, so a request to
///      `/user?bind=0x…` puts the wallet inside notarised data, and this contract
///      can check that leaf against `walletAddress` the way it already checks the
///      handle. Moving GitHub proving into the browser, as X and Google do, takes
///      the OAuth backend out of the trust model entirely.
///
///      **No OAuth-app pinning, and none to drop.** The MPC proof carries no
///      client_id claim.
///
///      **The response shape is this contract's own.** `handlePrefix` and the
///      id delimiters say how GitHub's JSON reads — a bare number ending at a
///      comma, where X quotes its id — and they are stored here rather than
///      read from somewhere else, so nothing has to be running for a name to
///      resolve.
///
///      **Which proofs work.** A claim naming nobody is one anybody could
///      redirect, so `IdentityNames` refuses a zero target. The proof must be
///      made out to the wallet that will hold the name, which is also the right
///      semantics: "I hold this address, bind this account to it."
contract GitHubIdentityVerifier is IIdentityVerifier, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// One notarized TLS session.
    struct FullTlsProof {
        bytes notarySignature;
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

    /// The proof plus the strings it is checked against. A verifier takes one
    /// `bytes` argument, so they travel together.
    struct GitHubProof {
        FullTlsProof tls;
        string domain;
        string handle;
        string userId;
        string endpoint;
    }

    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;
    uint256 public constant PROOF_TTL = 1 hours;

    /// @dev The one domain this verifier speaks for.
    ///
    ///      This must be pinned. The notary signs the domain's HASH, so the
    ///      contract has to be told which string that is — and the proof
    ///      therefore carries the domain as a field. Without this check a
    ///      notarized session of any other host verifies here and binds a name
    ///      under the platform id this contract is registered for. The domain
    ///      is proved, which makes it honest about WHICH host answered; it says
    ///      nothing about whether that is the host this contract speaks for.
    string private constant PLATFORM_DOMAIN = "api.github.com";

    /// @notice The Notary contract whose attestations this accepts. The digest
    ///         still binds `address(this)`; only the check itself is shared.
    INotary public notaryContract;

    /// @notice How GitHub's `/user` response reads.
    ///
    /// @dev The bytes revealed in the transcript are matched against
    ///      `handlePrefix + handle + '"'` and `idPrefix + userId + idSuffix`,
    ///      so these say where a handle and an id begin and end. GitHub's id is
    ///      a bare number ending at a comma; X quotes its own.
    struct ResponseShape {
        string endpoint;
        string handlePrefix;
        string idPrefix;
        string idSuffix;
    }

    /// @notice This contract's own view of the response, stored rather than
    ///         read from anywhere. A name has to resolve whether or not
    ///         anything else is running.
    ///
    /// @dev Owner-settable, because an API can change its response and a naming
    ///      system that could not follow would simply stop accepting proofs.
    ResponseShape public shape;

    error ZeroSigner();
    error EmptyResponseShape();
    error FutureProof();
    error StaleProof();
    error WrongEndpoint();
    error DomainHashMismatch();
    error NotaryVerificationFailed();
    error MerklePathTooLong();
    error InvalidMerkleProof();
    error UserIdRequired();
    error IdNotSupported();
    /// The proof is for a different platform than this verifier speaks for.
    error WrongPlatform(string domain);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param notaryContract_ The shared Notary contract (INotary). Notary key
    ///        rotation happens THERE; this contract holds only the pointer.
    function initialize(address owner_, address notaryContract_, ResponseShape calldata shape_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        if (notaryContract_ == address(0)) revert ZeroSigner();
        notaryContract = INotary(notaryContract_);
        _setResponseShape(shape_);
    }

    /// @notice The current notary signer, read through the Notary contract.
    function notary() external view returns (address) {
        return notaryContract.notary();
    }

    /// @notice Follow a change in GitHub's response.
    function setResponseShape(ResponseShape calldata shape_) external onlyOwner {
        _setResponseShape(shape_);
    }

    function _setResponseShape(ResponseShape calldata shape_) private {
        // An empty prefix matches at every position, so a leaf built from one
        // would prove nothing about where the value sits. `idSuffix` may be
        // empty: a value that runs to the end of the revealed bytes has nothing
        // after it to name.
        if (
            bytes(shape_.endpoint).length == 0 || bytes(shape_.handlePrefix).length == 0
                || bytes(shape_.idPrefix).length == 0
        ) {
            revert EmptyResponseShape();
        }
        shape = shape_;
    }

    function platformName() external pure override returns (string memory) {
        return PLATFORM_DOMAIN;
    }

    /// @inheritdoc IIdentityVerifier
    function verify(bytes calldata proof) external view override returns (IdentityClaim memory claim) {
        GitHubProof memory p = abi.decode(proof, (GitHubProof));
        FullTlsProof memory t = p.tls;

        // First, because everything below reads the platform's configuration
        // under this domain: checking it last would verify a full X proof
        // against X's response shape and only then notice the platform.
        if (keccak256(bytes(p.domain)) != keccak256(bytes(PLATFORM_DOMAIN))) revert WrongPlatform(p.domain);

        if (t.timestamp > block.timestamp + CLOCK_SKEW_GRACE) revert FutureProof();
        if (block.timestamp > t.timestamp + PROOF_TTL) revert StaleProof();

        ResponseShape memory sh = shape;
        if (keccak256(bytes(p.endpoint)) != keccak256(bytes(sh.endpoint))) revert WrongEndpoint();
        if (keccak256(bytes(p.domain)) != t.domainHash) revert DomainHashMismatch();

        _verifyNotarySignature(t);

        _verifyLeaf(t.domainPath, t.transcriptRoot, "domain:", bytes(p.domain));
        _verifyLeaf(t.endpointPath, t.transcriptRoot, "endpoint:", bytes(p.endpoint));
        _verifyLeaf(t.usernamePath, t.transcriptRoot, "recv:", abi.encodePacked(sh.handlePrefix, p.handle, '"'));

        if (bytes(p.userId).length == 0) revert UserIdRequired();
        _verifyLeaf(t.idPath, t.transcriptRoot, "recv:", abi.encodePacked(sh.idPrefix, p.userId, sh.idSuffix));

        // The wallet the proof was made out to. Zero on a registration proof,
        // which `IdentityNames` refuses — see the contract comment.
        return
            IdentityClaim({
                userId: p.userId, handle: p.handle, target: t.walletAddress, observedAt: uint64(t.timestamp)
            });
    }

    /// @dev Bound to this contract. The naming system's notary is told which
    ///      address it is attesting to, so a signature made out to anything
    ///      else — another deployment, another product — does not recover here.
    function _verifyNotarySignature(FullTlsProof memory t) private view {
        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                t.domainHash,
                t.clientRandom,
                t.serverRandom,
                keccak256(t.serverEphemeralKey),
                t.transcriptRoot,
                t.timestamp
            )
        );
        if (!notaryContract.verify(digest, t.notarySignature)) revert NotaryVerificationFailed();
    }

    function _verifyLeaf(bytes32[] memory path, bytes32 root, string memory prefix, bytes memory value) private pure {
        if (path.length > 32) revert MerklePathTooLong();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(prefix, value))));
        if (!MerkleProof.verify(path, root, leaf)) revert InvalidMerkleProof();
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Renouncing would leave no way to rotate a key or follow a change
    ///      in the response.
    function renounceOwnership() public pure override {
        revert("renounce disabled");
    }
}
