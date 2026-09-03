// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IRegistry} from "./IRegistry.sol";
import {WalletFactory} from "./WalletFactory.sol";
import {WebWallet} from "./WebWallet.sol";
import {IZkSessionVerifier} from "./zk/IZkSessionVerifier.sol";
import {IOidcVerifier} from "./oidc/IOidcVerifier.sol";
import {INotary} from "../notary/INotary.sol";

/// @title Registry — session registration and identity linking with 2-of-2 proof verification.
contract Registry is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, PausableUpgradeable, IRegistry {
    using ECDSA for bytes32;

    // ─── Proof verification state ──────────────────────────────────

    /// @notice Tolerance for proof timestamps that land slightly ahead of
    ///         `block.timestamp`. Eden's block head typically trails wall
    ///         clock by a handful of seconds, so a freshly notarized proof
    ///         would otherwise revert with `FutureProof`.
    uint256 public constant CLOCK_SKEW_GRACE = 5 minutes;

    struct HandleEntry {
        string platform;
        string handle;
        string userId; // immutable platform id; "" for pre-refactor entries
    }

    /// @notice Per-domain platform configuration for on-chain verification.
    struct PlatformConfig {
        string endpoint; // expected API endpoint path, e.g. "/user"
        string handlePrefix; // JSON prefix including quotes/colon/whitespace, e.g. '"login":"' or '"email": "'
        string idPrefix; // JSON prefix of the immutable id. Empty disables id-binding.
        string idSuffix; // JSON suffix anchoring the id's end: '"' for quoted (X), ',' for a bare number (GitHub)
    }

    struct IdMeta {
        string handle; // current display handle for this id
        uint256 verifiedAt; // block.timestamp of last id-handle proof
    }

    /// @custom:storage-location erc7201:dyaka.storage.Registry
    struct RegistryStorage {
        INotary notaryContract; // the shared Notary contract (verifies notary attestations)
        address backend; // backend signer
        WalletFactory walletFactory;
        /// Replay protection: sessionAddress to already used (flat, globally unique).
        mapping(address => bool) usedSessionKeys;
        /// wallet contract to array of (platform, handle, id) tuples.
        mapping(address => HandleEntry[]) contract_to_handles;
        /// domain to platform config. A platform is enabled if its endpoint is not empty.
        mapping(string => PlatformConfig) platformConfigs;
        /// Per-platform ZK verifier. Each verifier owns its circuit, notary key
        /// and platform bindings. The Registry dispatches by platform string
        /// and tracks only session keys and nullifiers.
        mapping(string => IZkSessionVerifier) zkVerifierOf;
        /// Replay protection: the domain-wrapped bearer nullifier from the
        /// verifier. The Registry consumes it one time.
        mapping(bytes32 => bool) usedBearerNullifiers;
        /// domain to OIDC verifier. A platform supports OIDC if its verifier is
        /// set. The owner manages these. The OIDC path is the alternative to
        /// the TLS-notary flow and gives the same claim shape.
        mapping(string => IOidcVerifier) oidcVerifierOf;
        mapping(string => mapping(string => address)) walletOf; // [platform][id] to wallet (TRUTH)
        mapping(string => mapping(string => IdMeta)) idMeta; // [platform][id] to meta (display)
        mapping(string => mapping(string => string)) handleHint; // [platform][handle] to id (re-pointable)
    }

    // keccak256(abi.encode(uint256(keccak256("dyaka.storage.Registry")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant REGISTRY_STORAGE = 0x42c0aa58641382e077ceeffba10b73e1be97f010be3e8a2a89d2914f8b201b00;

    /// @dev All state of this contract is under one namespaced root. The state
    ///      cannot collide with the ERC-7201 namespaces of the OpenZeppelin
    ///      upgradeable base contracts. An upgrade can append a field without
    ///      slot arithmetic. Append only. Do not reorder or remove a field.
    function _s() private pure returns (RegistryStorage storage $) {
        assembly {
            $.slot := REGISTRY_STORAGE
        }
    }

    // ─── Storage reads (the ABI the public variables gave) ─────────

    /// @notice The Notary contract this Registry routes attestation checks through.
    function notaryContract() external view returns (address) {
        return address(_s().notaryContract);
    }

    /// @notice The current notary signer, read through the Notary contract.
    ///         Kept so observers keep the read they had when the key was local.
    function notary() external view returns (address) {
        return _s().notaryContract.notary();
    }

    function backend() external view returns (address) {
        return _s().backend;
    }

    function walletFactory() external view returns (WalletFactory) {
        return _s().walletFactory;
    }

    function usedSessionKeys(address sessionAddr) external view returns (bool) {
        return _s().usedSessionKeys[sessionAddr];
    }

    function contract_to_handles(address wallet, uint256 index)
        external
        view
        returns (string memory platform, string memory handle, string memory userId)
    {
        HandleEntry storage entry = _s().contract_to_handles[wallet][index];
        return (entry.platform, entry.handle, entry.userId);
    }

    function platformConfigs(string calldata domain)
        external
        view
        returns (string memory endpoint, string memory handlePrefix, string memory idPrefix, string memory idSuffix)
    {
        PlatformConfig storage cfg = _s().platformConfigs[domain];
        return (cfg.endpoint, cfg.handlePrefix, cfg.idPrefix, cfg.idSuffix);
    }

    function zkVerifierOf(string calldata domain) external view returns (IZkSessionVerifier) {
        return _s().zkVerifierOf[domain];
    }

    function usedBearerNullifiers(bytes32 nullifier) external view returns (bool) {
        return _s().usedBearerNullifiers[nullifier];
    }

    function oidcVerifierOf(string calldata domain) external view returns (IOidcVerifier) {
        return _s().oidcVerifierOf[domain];
    }

    function walletOf(string calldata platform, string calldata userId) external view returns (address) {
        return _s().walletOf[platform][userId];
    }

    function idMeta(string calldata platform, string calldata userId)
        external
        view
        returns (string memory handle, uint256 verifiedAt)
    {
        IdMeta storage meta = _s().idMeta[platform][userId];
        return (meta.handle, meta.verifiedAt);
    }

    function handleHint(string calldata platform, string calldata handle) external view returns (string memory) {
        return _s().handleHint[platform][handle];
    }

    /// @notice Convenience read for ZK-domain support.
    function isZkDomainSupported(string calldata domain) public view returns (bool) {
        return address(_s().zkVerifierOf[domain]) != address(0);
    }

    // ─── Proof struct (Merkle paths included) ──────────────────────

    struct FullTlsProof {
        bytes notarySignature;
        bytes backendSignature;
        /// Session keypair public address generated by the prover's browser;
        /// becomes the session key registered against the wallet. Signed
        /// into the _s().backend digest, so attackers cannot rebind it.
        address userAddress;
        /// Bound to _s().backend sig. `address(0)` for register_session,
        /// `msg.sender` for linkIdentity.
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
        bytes32[] idPath; // path for the "id":"<id>" recv leaf; empty when userId is ""
    }

    // ─── Events ────────────────────────────────────────────────────

    event SessionRegistered(string platform, string handle, address indexed wallet, address sessionAddr);
    event IdentityLinked(string platform, string handle, address indexed wallet);
    /// Emitted when an id's current handle changes (rename). Lets the indexer
    /// refresh the off-chain label keyed by the immutable id.
    event HandleChanged(string platform, string userId, string handle);

    // ─── Errors ────────────────────────────────────────────────────

    error InvalidMerkleProof();
    error SessionKeyAlreadyUsed();
    error InvalidNotarySignature();
    error InvalidBackendSignature();
    error StaleProof();
    error FutureProof();
    error MerklePathTooLong();
    error NotRegisteredWallet();
    error IdentityAlreadyLinked();
    error UserIdRequired();
    error UnknownId();
    error UnsupportedPlatform();
    error WrongEndpoint();
    error ZkVerifierNotSet();
    error BearerNullifierUsed();
    error ProofExpired();
    error WrongWalletAddr();
    error JwtExpired();
    error OidcVerifierNotSet();
    error LinkWalletMismatch();

    // ─── Initializer ──────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param _notaryContract The shared Notary contract (INotary) every
    ///        attestation check routes through.
    function initialize(address _notaryContract, address _backend, address _walletFactory, address _owner)
        external
        initializer
    {
        __Ownable_init(_owner);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        require(_notaryContract != address(0), "zero notary contract");
        require(_backend != address(0), "zero _s().backend");
        require(_walletFactory != address(0), "zero factory");
        _s().notaryContract = INotary(_notaryContract);
        _s().backend = _backend;
        _s().walletFactory = WalletFactory(_walletFactory);
    }

    /// @notice Pause state-changing entrypoints. Owner-only emergency stop and
    ///         migration-cutover gate (covers the permissionless ZK/OIDC paths a
    ///         _s().backend-pause can't reach). Admin/owner fns stay callable.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Resume after a pause.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ─── Admin ─────────────────────────────────────────────────────

    function setBackend(address _backend) external onlyOwner {
        require(_backend != address(0), "zero _s().backend");
        _s().backend = _backend;
    }

    /// @notice Register or update a supported platform. `idPrefix`/`idSuffix`
    ///         enable id-binding (X: '"id":"' + '"'; GitHub: '"id":' + ','); pass
    ///         empty idPrefix to leave it off. idSuffix anchors the id's end.
    function setPlatform(
        string calldata domain,
        string calldata endpoint,
        string calldata handlePrefix,
        string calldata idPrefix,
        string calldata idSuffix
    ) external onlyOwner {
        require(bytes(domain).length > 0, "empty domain");
        require(bytes(endpoint).length > 0, "empty endpoint");
        require(bytes(handlePrefix).length > 0, "empty key");
        _s().platformConfigs[domain] = PlatformConfig(endpoint, handlePrefix, idPrefix, idSuffix);
    }

    /// @notice Remove a platform (clears config, disabling registrations).
    function removePlatform(string calldata domain) external onlyOwner {
        delete _s().platformConfigs[domain];
    }

    /// @notice Set or clear the ZK verifier for a platform. Pass
    ///         `IZkSessionVerifier(address(0))` to disable.
    function setZkVerifier(string calldata domain, IZkSessionVerifier verifier) external onlyOwner {
        require(bytes(domain).length > 0, "empty domain");
        _s().zkVerifierOf[domain] = verifier;
    }

    /// @notice Set or clear the OIDC verifier for a platform. Pass
    ///         `IOidcVerifier(address(0))` to disable.
    function setOidcVerifier(string calldata platform, IOidcVerifier verifier) external onlyOwner {
        require(bytes(platform).length > 0, "empty platform");
        _s().oidcVerifierOf[platform] = verifier;
    }

    // ─── Session registration ──────────────────────────────────────

    /// @notice Register a session address for a social identity. The session
    ///         key is `proof.userAddress` (notary + backend signed). No
    ///         loose `sessionAddr` parameter -- a previous version of this
    ///         function let a mempool front-runner substitute the session
    ///         key without invalidating the signatures.
    function register_session(
        FullTlsProof calldata proof,
        string calldata domain,
        string calldata username,
        string calldata userId,
        string calldata endpoint
    ) external whenNotPaused {
        // Session key is proof.userAddress (notary + backend signed); no loose
        // sessionAddr param (anti front-run). New identity → walletAddress must
        // be the zero sentinel so the factory deploys the wallet.
        if (proof.walletAddress != address(0)) revert WrongWalletAddr();

        _verifyProof(proof, domain, username, userId, endpoint);

        _registerHandle(domain, username, userId, proof.userAddress);
    }

    // ─── ZK session registration (dispatcher) ──────────────────────

    /// @notice Register a session via the platform's configured
    ///         `IZkSessionVerifier`. The verifier owns all platform-
    ///         specific logic (circuit, notary, attestation shape); the
    ///         Registry only enforces dispatch + global session-key and
    ///         nullifier replay protection, then deploys the wallet and
    ///         registers the session.
    function register_session_zk(string calldata platform, bytes calldata zkProof) external whenNotPaused {
        IZkSessionVerifier verifier = _s().zkVerifierOf[platform];
        if (address(verifier) == address(0)) revert ZkVerifierNotSet();

        (
            string memory handle,
            address sessionAddr,
            address walletAddress,
            uint256 expiresAt,
            bytes32 nullifier,
            string memory userId
        ) = verifier.verifyAndExtract(zkProof);

        // Factory deploys the wallet: PI wallet must be the zero sentinel.
        if (walletAddress != address(0)) revert WrongWalletAddr();
        if (block.timestamp >= expiresAt) revert ProofExpired();
        _consumeNullifier(nullifier);
        _registerHandle(platform, handle, userId, sessionAddr);
    }

    /// Link a ZK identity to the *calling* wallet. PI walletAddress must
    /// equal msg.sender so a leaked proof cannot be replayed from another
    /// wallet -- the binding is committed inside the ZK proof.
    function link_identity_zk(string calldata platform, bytes calldata zkProof) external whenNotPaused {
        IZkSessionVerifier verifier = _s().zkVerifierOf[platform];
        if (address(verifier) == address(0)) revert ZkVerifierNotSet();

        (
            string memory handle,
            address sessionAddr,
            address walletAddress,
            uint256 expiresAt,
            bytes32 nullifier,
            string memory userId
        ) = verifier.verifyAndExtract(zkProof);

        if (walletAddress != msg.sender) revert WrongWalletAddr();
        if (block.timestamp >= expiresAt) revert ProofExpired();
        _consumeNullifier(nullifier);
        _linkHandle(platform, handle, userId, sessionAddr);
    }

    // ─── Shared internals ──────────────────────────────────────────

    /// One-shot consume of a ZK bearer nullifier (replay guard).
    function _consumeNullifier(bytes32 nullifier) internal {
        if (_s().usedBearerNullifiers[nullifier]) revert BearerNullifierUsed();
        _s().usedBearerNullifiers[nullifier] = true;
    }

    /// @dev Point `handle` at `userId` as the id's current label. Clears the id's
    /// PREVIOUS handle hint (rename) so an abandoned handle stops resolving here —
    /// but only if that hint still points to this id (not recycled to another).
    function _bindHandle(string memory platform, string memory handle, string memory userId) internal {
        string memory prevHandle = _s().idMeta[platform][userId].handle;
        bool renamed = bytes(prevHandle).length != 0 && keccak256(bytes(prevHandle)) != keccak256(bytes(handle));
        if (renamed && keccak256(bytes(_s().handleHint[platform][prevHandle])) == keccak256(bytes(userId))) {
            delete _s().handleHint[platform][prevHandle];
        }
        _s().idMeta[platform][userId] = IdMeta(handle, block.timestamp);
        _s().handleHint[platform][handle] = userId;
        if (renamed) emit HandleChanged(platform, userId, handle);
    }

    /// Deploy-or-find the wallet for `(platform, handle)` and register the
    /// session key. Used by every `register_session_*` (new-identity) path.
    function _registerHandle(string memory platform, string memory handle, string memory userId, address sessionAddr)
        internal
    {
        // Escrow is keyed by the immutable platform id — never the mutable
        // handle. No handle-key fallback; a registration without an id is
        // rejected (legacy handle-keyed wallets are migrated separately).
        if (bytes(userId).length == 0) revert UserIdRequired();
        require(sessionAddr != address(0), "zero session");
        if (_s().usedSessionKeys[sessionAddr]) revert SessionKeyAlreadyUsed();
        _s().usedSessionKeys[sessionAddr] = true;

        // ── (platform, id) is the truth ──
        address wallet = _s().walletOf[platform][userId];
        if (wallet == address(0)) {
            wallet = _s().walletFactory.deploy_web_wallet(platform, handle, userId);
            _s().walletOf[platform][userId] = wallet;
            _s().contract_to_handles[wallet].push(HandleEntry(platform, handle, userId));
            // New id→wallet binding only; returning users emit SessionRegistered.
            emit HandleRegistered(platform, handle, wallet);
        }
        _bindHandle(platform, handle, userId);
        WebWallet(payable(wallet)).register_session(platform, handle, userId, sessionAddr);
        emit SessionRegistered(platform, handle, wallet, sessionAddr);
    }

    /// Attach `(platform, handle)` to the calling registered wallet and
    /// register the session key. Used by every `link_*` path; the caller
    /// must have verified the proof is bound to `msg.sender`.
    function _linkHandle(string memory platform, string memory handle, string memory userId, address sessionAddr)
        internal
    {
        _linkHandleTo(msg.sender, platform, handle, userId, sessionAddr);
    }

    /// Link an identity to an EXPLICIT wallet rather than `msg.sender`.
    ///
    /// A caller passing a wallet other than `msg.sender` must have already
    /// established that the wallet authorized the link — e.g. a signature from
    /// one of the wallet's existing session keys carried inside the proof, which
    /// is what would make such a transaction sponsorable. No such caller exists
    /// today; `_linkHandle` passes `msg.sender`.
    function _linkHandleTo(
        address wallet,
        string memory platform,
        string memory handle,
        string memory userId,
        address sessionAddr
    ) internal {
        if (_s().contract_to_handles[wallet].length == 0) revert NotRegisteredWallet();
        if (bytes(userId).length == 0) revert UserIdRequired();
        require(sessionAddr != address(0), "zero session");
        if (_s().usedSessionKeys[sessionAddr]) revert SessionKeyAlreadyUsed();
        _s().usedSessionKeys[sessionAddr] = true;

        // ── an id maps to exactly one wallet ──
        address linked = _s().walletOf[platform][userId];
        if (linked != address(0) && linked != wallet) revert IdentityAlreadyLinked();
        // Only append a HandleEntry the first time this id links to this wallet.
        // Re-linking the same (platform, userId) just refreshes the label/session;
        // a duplicate entry would break the one-entry-per-(platform,userId) invariant.
        if (linked != wallet) {
            _s().walletOf[platform][userId] = wallet;
            _s().contract_to_handles[wallet].push(HandleEntry(platform, handle, userId));
        }
        _bindHandle(platform, handle, userId);
        WebWallet(payable(wallet)).register_session(platform, handle, userId, sessionAddr);
        emit IdentityLinked(platform, handle, wallet);
    }

    // ─── OIDC session registration ─────────────────────────────────

    /// @notice OIDC variant of `register_session`. The caller passes an
    ///         opaque OIDC proof (bytes); the configured `IOidcVerifier`
    ///         for `platform` validates it and extracts the user's
    ///         identity, session key, and JWT expiry. Downstream wallet
    ///         deploy + event emission is identical to the TLSN flow, so
    ///         the indexer treats OIDC registrations the same as any
    ///         other handle registration.
    ///
    /// @param platform   Platform domain string, e.g. `"www.googleapis.com"`.
    /// @param oidcProof  Opaque payload understood by the configured
    ///                   verifier (for `GoogleOidcVerifier`: ABI-encoded
    ///                   `UserProof` carrying the Honk proof, public
    ///                   inputs, and the email + session-key plaintexts).
    function register_session_oidc(string calldata platform, bytes calldata oidcProof) external whenNotPaused {
        IOidcVerifier verifier = _s().oidcVerifierOf[platform];
        if (address(verifier) == address(0)) revert OidcVerifierNotSet();

        (string memory handle, address sessionAddr, uint256 jwtExp, string memory userId) =
            verifier.verifyAndExtract(oidcProof);

        // The verifier already enforces JWT freshness against its own
        // CLOCK_SKEW_GRACE, but the Registry re-checks against its own
        // tolerance so all session-key bindings share the same liveness
        // contract regardless of which provider validated the proof.
        if (jwtExp + CLOCK_SKEW_GRACE <= block.timestamp) revert JwtExpired();

        // Escrow keys on the immutable JWT `sub`, not the mutable email handle.
        _registerHandle(platform, handle, userId, sessionAddr);
    }

    // ─── OIDC identity linking ─────────────────────────────────────

    /// @notice Link an OIDC identity (e.g. Gmail) to the *existing* wallet
    ///         that calls this function, instead of deploying a new one
    ///         (the `register_session_oidc` behaviour).
    ///
    ///         Front-run safe: the OIDC `nonce` is bound to the calling
    ///         wallet — `verifyAndExtract` returns it and we require it to
    ///         equal `msg.sender`. The nonce lives inside the provider-signed
    ///         JWT, so a stolen proof cannot be replayed by another wallet.
    ///
    /// @param platform     Platform domain string, e.g. `"www.googleapis.com"`.
    /// @param oidcProof    Verifier proof whose JWT `nonce` is this wallet's address.
    /// @param sessionAddr  Session key to register for the linked handle.
    function link_identity_oidc(string calldata platform, bytes calldata oidcProof, address sessionAddr)
        external
        whenNotPaused
    {
        // Caller must be a registered WebWallet (its session key authorized
        // this via WebWallet.execute) — same consent gate as linkIdentity.
        if (_s().contract_to_handles[msg.sender].length == 0) revert NotRegisteredWallet();

        IOidcVerifier verifier = _s().oidcVerifierOf[platform];
        if (address(verifier) == address(0)) revert OidcVerifierNotSet();

        (string memory handle, address boundWallet, uint256 jwtExp, string memory userId) =
            verifier.verifyAndExtract(oidcProof);

        // The JWT `nonce` is bound to the linking wallet (returned as the
        // session/bound address), so the proof is only usable by that wallet
        // — closes the front-run window.
        if (boundWallet != msg.sender) revert LinkWalletMismatch();
        if (jwtExp + CLOCK_SKEW_GRACE <= block.timestamp) revert JwtExpired();

        // Escrow keys on the immutable JWT `sub`. `sessionAddr` is the session
        // key the caller wants registered for the linked handle.
        _linkHandle(platform, handle, userId, sessionAddr);
    }

    // ─── Identity linking ──────────────────────────────────────────

    /// Link an additional social identity to msg.sender. Backend-signed
    /// `proof.walletAddress` must equal `msg.sender` to prevent mempool replay.
    function linkIdentity(
        string calldata platform,
        string calldata handle,
        string calldata userId,
        FullTlsProof calldata proof,
        string calldata endpoint
    ) external whenNotPaused {
        // Cheap fail-fast (also enforced by _linkHandle).
        if (_s().contract_to_handles[msg.sender].length == 0) revert NotRegisteredWallet();
        if (proof.walletAddress != msg.sender) revert WrongWalletAddr();

        _verifyProof(proof, platform, handle, userId, endpoint);

        // Delegate to the shared helper (guards + binding live there).
        _linkHandle(platform, handle, userId, proof.userAddress);
    }

    /// @notice Re-point a handle's hint to its id with a fresh attestation. Permissionless.
    function refreshHandleHint(
        string calldata platform,
        string calldata id,
        string calldata handle,
        FullTlsProof calldata proof,
        string calldata endpoint
    ) external whenNotPaused {
        _verifyProof(proof, platform, handle, id, endpoint);
        if (_s().walletOf[platform][id] == address(0)) revert UnknownId();
        _bindHandle(platform, handle, id);
    }

    /// @inheritdoc IRegistry
    /// @dev A handle resolves through the id that it points to now. The old
    ///      `handle_to_contract` fallback is removed. No code has written that
    ///      mapping since handles stopped being the truth, so the fallback
    ///      always returned zero. This namespace is append-only, and a dead
    ///      slot in it stays forever.
    function resolve(string calldata platform, string calldata handle) external view returns (address) {
        string storage id = _s().handleHint[platform][handle];
        if (bytes(id).length == 0) return address(0);
        return _s().walletOf[platform][id];
    }

    /// @inheritdoc IRegistry
    function resolveById(string calldata platform, string calldata id) external view returns (address) {
        return _s().walletOf[platform][id];
    }

    // ─── Views ─────────────────────────────────────────────────────

    /// @notice Return the platform config for a domain. Empty endpoint means unconfigured.
    function getPlatform(string calldata domain)
        external
        view
        returns (string memory endpoint, string memory handlePrefix)
    {
        PlatformConfig storage pc = _s().platformConfigs[domain];
        return (pc.endpoint, pc.handlePrefix);
    }

    function getHandles(address wallet) external view returns (string[] memory platforms, string[] memory handles) {
        HandleEntry[] storage entries = _s().contract_to_handles[wallet];
        uint256 len = entries.length;
        platforms = new string[](len);
        handles = new string[](len);
        for (uint256 i = 0; i < len; i++) {
            platforms[i] = entries[i].platform;
            // Frozen handle — matches the legacy handle-keyed slot kept for
            // pre-id consumers. For a rename-safe DISPLAY handle
            // use getCurrentHandles (idMeta-backed).
            handles[i] = entries[i].handle;
        }
    }

    /// @notice Like getHandles but returns each id's CURRENT handle (idMeta),
    ///         rename-safe — for display, never for claim-key computation.
    function getCurrentHandles(address wallet)
        external
        view
        returns (string[] memory platforms, string[] memory handles)
    {
        HandleEntry[] storage entries = _s().contract_to_handles[wallet];
        uint256 len = entries.length;
        platforms = new string[](len);
        handles = new string[](len);
        for (uint256 i = 0; i < len; i++) {
            platforms[i] = entries[i].platform;
            string memory current = _s().idMeta[entries[i].platform][entries[i].userId].handle;
            handles[i] = bytes(current).length > 0 ? current : entries[i].handle;
        }
    }

    /// @notice Platform user-ids linked to `wallet`, parallel to getHandles.
    ///         The authoritative claim key for id-keyed accounting. "" for legacy entries.
    function getUserIds(address wallet) external view returns (string[] memory platforms, string[] memory userIds) {
        HandleEntry[] storage entries = _s().contract_to_handles[wallet];
        uint256 len = entries.length;
        platforms = new string[](len);
        userIds = new string[](len);
        for (uint256 i = 0; i < len; i++) {
            platforms[i] = entries[i].platform;
            userIds[i] = entries[i].userId;
        }
    }

    // ─── Internal: full proof verification ─────────────────────────

    /// @notice Verify timestamps, platform/endpoint, domain hash, 2-of-2 sigs,
    ///         and the 4 merkle leaves. Shared by register/link/refresh.
    function _verifyProof(
        FullTlsProof calldata proof,
        string calldata domain,
        string calldata handle,
        string calldata userId,
        string calldata endpoint
    ) internal view returns (PlatformConfig storage pc) {
        if (proof.timestamp > block.timestamp + CLOCK_SKEW_GRACE) revert FutureProof();
        if (block.timestamp > proof.timestamp + 1 hours) revert StaleProof();

        pc = _s().platformConfigs[domain];
        if (bytes(pc.endpoint).length == 0) revert UnsupportedPlatform();
        if (keccak256(bytes(endpoint)) != keccak256(bytes(pc.endpoint))) revert WrongEndpoint();

        require(keccak256(bytes(domain)) == proof.domainHash, "domain hash mismatch");

        _verifyNotarySignature(proof);
        _verifyBackendSignature(proof);

        _verifyLeaf(proof.domainPath, proof.transcriptRoot, "domain:", bytes(domain));
        _verifyUsernameLeaf(proof.usernamePath, proof.transcriptRoot, pc.handlePrefix, handle);
        _verifyLeaf(proof.endpointPath, proof.transcriptRoot, "endpoint:", bytes(endpoint));
        _verifyId(proof, pc, userId);
    }

    // ─── Internal: signature verification ──────────────────────────

    function _verifyNotarySignature(FullTlsProof calldata proof) internal view {
        // Domain-separated by (chainId, this contract). The notary mirror
        // is `crypto::compute_notary_digest` in the original monorepo's
        // auth crate. The Notary contract owns the attestation check
        // itself (EIP-191 + recover + signer compare today).
        bytes32 proofDigest = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                proof.domainHash,
                proof.clientRandom,
                proof.serverRandom,
                keccak256(proof.serverEphemeralKey),
                proof.transcriptRoot,
                proof.timestamp
            )
        );
        if (!_s().notaryContract.verify(proofDigest, proof.notarySignature)) revert InvalidNotarySignature();
    }

    function _verifyBackendSignature(FullTlsProof calldata proof) internal view {
        bytes32 backendDigest =
            keccak256(abi.encode(proof.userAddress, proof.walletAddress, proof.transcriptRoot, proof.timestamp));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", backendDigest));
        address signer = ethHash.recover(proof.backendSignature);
        if (signer != _s().backend) revert InvalidBackendSignature();
    }

    function _verifyLeaf(bytes32[] calldata path, bytes32 root, string memory prefix, bytes memory value)
        internal
        pure
    {
        if (path.length > 32) revert MerklePathTooLong();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(prefix, value))));
        if (!MerkleProof.verify(path, root, leaf)) revert InvalidMerkleProof();
    }

    /// @notice Verify the immutable-id recv leaf.
    ///         Snippet = idPrefix + id + idSuffix. The suffix anchors the id's
    ///         end (closing `"` for X, `,` for GitHub's bare number) so a
    ///         truncated number can't match a longer real id. An empty userId is
    ///         rejected here for fail-early parity with `_registerHandle` /
    ///         `_linkHandle` (and the ZK/OIDC verifiers), which also require an id.
    function _verifyId(FullTlsProof calldata proof, PlatformConfig storage pc, string calldata userId) internal view {
        if (bytes(userId).length == 0) revert UserIdRequired();
        require(bytes(pc.idPrefix).length != 0, "id not supported");
        if (proof.idPath.length > 32) revert MerklePathTooLong();
        bytes memory snippet = abi.encodePacked(pc.idPrefix, userId, pc.idSuffix);
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked("recv:", snippet))));
        if (!MerkleProof.verify(proof.idPath, proof.transcriptRoot, leaf)) revert InvalidMerkleProof();
    }

    /// @notice Verify the username Merkle leaf matches the expected JSON snippet.
    ///         handlePrefix already includes quotes, colon, and any whitespace (e.g. `"login":"` or `"email": "`).
    function _verifyUsernameLeaf(
        bytes32[] calldata path,
        bytes32 root,
        string memory handlePrefix,
        string memory username
    ) internal pure {
        if (path.length > 32) revert MerklePathTooLong();
        bytes memory snippet = abi.encodePacked(handlePrefix, username, '"');
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked("recv:", snippet))));
        if (!MerkleProof.verify(path, root, leaf)) revert InvalidMerkleProof();
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
