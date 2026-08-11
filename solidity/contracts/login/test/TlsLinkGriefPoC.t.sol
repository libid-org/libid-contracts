// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Registry} from "../Registry.sol";
import {WalletFactory} from "../WalletFactory.sol";
import {WebWallet} from "../WebWallet.sol";

/// End-to-end PoC: walletAddress baked into the backend signature blocks
/// proof replay from a different `msg.sender`. Victim's proof is signed
/// with `walletAddress = W_v`; attacker tries to replay from W_atk →
/// contract requires `proof.walletAddress == msg.sender` → revert.
contract TlsLinkGriefPoC is Test {
    Registry registry;
    WalletFactory factory;

    uint256 constant NOTARY_KEY = 0xBEEF;
    uint256 constant BACKEND_KEY = 0xBEED;
    uint256 constant VICTIM_BOOT_KEY = 0xCA75; // signs victim wallet's executes
    uint256 constant VICTIM_LINK_KEY = 0x713C71; // userAddress inside the leaked link proof
    uint256 constant ATTACKER_BOOT_KEY = 0xA77ACE; // signs attacker wallet's executes

    address notaryAddr;
    address backendAddr;
    address victimBootAddr;
    address victimLinkAddr;
    address attackerBootAddr;

    string constant PLATFORM = "github.com";
    string constant ENDPOINT = "/user";
    string constant HANDLE_PREFIX = '"login":"';
    string constant VICTIM_TARGET = "victim";

    function setUp() public {
        notaryAddr = vm.addr(NOTARY_KEY);
        backendAddr = vm.addr(BACKEND_KEY);
        victimBootAddr = vm.addr(VICTIM_BOOT_KEY);
        victimLinkAddr = vm.addr(VICTIM_LINK_KEY);
        attackerBootAddr = vm.addr(ATTACKER_BOOT_KEY);

        WebWallet walletImpl = new WebWallet();
        WalletFactory fImpl = new WalletFactory();
        factory = WalletFactory(
            address(
                new ERC1967Proxy(
                    address(fImpl),
                    abi.encodeCall(WalletFactory.initialize, (address(this), address(walletImpl), address(1)))
                )
            )
        );
        Registry rImpl = new Registry();
        registry = Registry(
            address(
                new ERC1967Proxy(
                    address(rImpl),
                    abi.encodeCall(Registry.initialize, (notaryAddr, backendAddr, address(factory), address(this)))
                )
            )
        );
        factory.setRegistry(address(registry));
        // GitHub-style bare-number id binding.
        registry.setPlatform(PLATFORM, ENDPOINT, HANDLE_PREFIX, '"id":', ",");
    }

    /// Deterministic numeric immutable id for a handle (identity keyed by id).
    function _idFor(string memory handle) internal pure returns (string memory) {
        return vm.toString(uint256(keccak256(bytes(handle))) % 1_000_000_000);
    }

    function _sortedHash(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _buildTree(string memory handle, string memory userId)
        internal
        pure
        returns (
            bytes32 root,
            bytes32[] memory dPath,
            bytes32[] memory uPath,
            bytes32[] memory ePath,
            bytes32[] memory idPath
        )
    {
        bytes32 dLeaf = keccak256(bytes.concat(keccak256(abi.encodePacked("domain:", bytes(PLATFORM)))));
        bytes memory snippet = abi.encodePacked(bytes(HANDLE_PREFIX), bytes(handle), '"');
        bytes32 uLeaf = keccak256(bytes.concat(keccak256(abi.encodePacked("recv:", snippet))));
        bytes32 eLeaf = keccak256(bytes.concat(keccak256(abi.encodePacked("endpoint:", bytes(ENDPOINT)))));
        // GitHub bare-number id leaf: "id":<id>,
        bytes memory idSnippet = abi.encodePacked('"id":', bytes(userId), ",");
        bytes32 idLeaf = keccak256(bytes.concat(keccak256(abi.encodePacked("recv:", idSnippet))));

        bytes32 p01 = _sortedHash(dLeaf, uLeaf);
        bytes32 p23 = _sortedHash(eLeaf, idLeaf);
        root = _sortedHash(p01, p23);

        dPath = new bytes32[](2);
        dPath[0] = uLeaf;
        dPath[1] = p23;

        uPath = new bytes32[](2);
        uPath[0] = dLeaf;
        uPath[1] = p23;

        ePath = new bytes32[](2);
        ePath[0] = idLeaf;
        ePath[1] = p01;

        idPath = new bytes32[](2);
        idPath[0] = eLeaf;
        idPath[1] = p01;
    }

    function _buildProof(string memory handle, string memory userId, address userAddr, address walletAddr)
        internal
        view
        returns (Registry.FullTlsProof memory)
    {
        (bytes32 root, bytes32[] memory dp, bytes32[] memory up, bytes32[] memory ep, bytes32[] memory idp) =
            _buildTree(handle, userId);

        bytes32 domainHash = keccak256(bytes(PLATFORM));
        bytes32 cr = bytes32(uint256(0xC1));
        bytes32 sr = bytes32(uint256(0x5E));
        bytes memory sek = hex"deadbeef";
        uint256 ts = block.timestamp;

        bytes32 nd =
            keccak256(abi.encode(block.chainid, address(registry), domainHash, cr, sr, keccak256(sek), root, ts));
        bytes32 nEth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", nd));
        (uint8 nv, bytes32 nr, bytes32 ns) = vm.sign(NOTARY_KEY, nEth);

        bytes32 bd = keccak256(abi.encode(userAddr, walletAddr, root, ts));
        bytes32 bEth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", bd));
        (uint8 bv, bytes32 br, bytes32 bs) = vm.sign(BACKEND_KEY, bEth);

        return Registry.FullTlsProof({
            notarySignature: abi.encodePacked(nr, ns, nv),
            backendSignature: abi.encodePacked(br, bs, bv),
            userAddress: userAddr,
            walletAddress: walletAddr,
            domainHash: domainHash,
            clientRandom: cr,
            serverRandom: sr,
            serverEphemeralKey: sek,
            transcriptRoot: root,
            timestamp: ts,
            domainPath: dp,
            usernamePath: up,
            endpointPath: ep,
            idPath: idp
        });
    }

    function _execSig(uint256 key, address walletAddr, address target, bytes memory data)
        internal
        view
        returns (bytes[] memory sigs)
    {
        uint256 n = WebWallet(payable(walletAddr)).nonce();
        bytes32 digest = keccak256(abi.encode(target, uint256(0), keccak256(data), n, block.chainid, walletAddr));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, eth);
        sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);
    }

    function _stripSelector(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = data[i + 4];
        }
    }

    /// Backend-signed walletAddress blocks proof replay from a different wallet.
    function test_TLS_walletBinding_blocksAttackerReplay_allowsVictimSubmission() public {
        // Bootstrap victim's wallet via register_session (walletAddress = 0).
        Registry.FullTlsProof memory vBoot =
            _buildProof("victim_boot", _idFor("victim_boot"), victimBootAddr, address(0));
        registry.register_session(vBoot, PLATFORM, "victim_boot", _idFor("victim_boot"), ENDPOINT);
        address victimWallet = registry.resolve(PLATFORM, "victim_boot");

        // Bootstrap attacker's wallet.
        Registry.FullTlsProof memory aBoot =
            _buildProof("attacker_boot", _idFor("attacker_boot"), attackerBootAddr, address(0));
        registry.register_session(aBoot, PLATFORM, "attacker_boot", _idFor("attacker_boot"), ENDPOINT);
        address attackerWallet = registry.resolve(PLATFORM, "attacker_boot");
        assertTrue(attackerWallet != victimWallet);

        // VICTIM composes a link tx — backend signs the proof bound to W_v.
        Registry.FullTlsProof memory linkProof =
            _buildProof(VICTIM_TARGET, _idFor(VICTIM_TARGET), victimLinkAddr, victimWallet);
        bytes memory victimLinkData = abi.encodeCall(
            Registry.linkIdentity, (PLATFORM, VICTIM_TARGET, _idFor(VICTIM_TARGET), linkProof, ENDPOINT)
        );

        // ATTACKER intercepts the raw calldata.
        bytes memory args = _stripSelector(victimLinkData);
        (
            string memory dPlatform,
            string memory dHandle,
            string memory dUserId,
            Registry.FullTlsProof memory stolenProof,
            string memory dEndpoint
        ) = abi.decode(args, (string, string, string, Registry.FullTlsProof, string));
        assertEq(stolenProof.walletAddress, victimWallet);

        // ATTACKER tries to replay from their own wallet. Contract requires
        // proof.walletAddress == msg.sender, which is now W_atk → revert.
        bytes memory attackerLinkData =
            abi.encodeCall(Registry.linkIdentity, (dPlatform, dHandle, dUserId, stolenProof, dEndpoint));
        bytes[] memory attackerSigs = _execSig(ATTACKER_BOOT_KEY, attackerWallet, address(registry), attackerLinkData);
        vm.expectRevert();
        WebWallet(payable(attackerWallet)).execute(address(registry), 0, attackerLinkData, attackerSigs);

        assertEq(registry.resolve(PLATFORM, VICTIM_TARGET), address(0));

        // VICTIM's own submission goes through (msg.sender == W_v).
        bytes[] memory victimSigs = _execSig(VICTIM_BOOT_KEY, victimWallet, address(registry), victimLinkData);
        WebWallet(payable(victimWallet)).execute(address(registry), 0, victimLinkData, victimSigs);
        assertEq(registry.resolve(PLATFORM, VICTIM_TARGET), victimWallet);
    }
}
