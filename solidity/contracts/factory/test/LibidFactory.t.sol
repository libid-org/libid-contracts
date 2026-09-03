// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {NotaryService} from "../../ceremony/NotaryService.sol";
import {Create3} from "../Create3.sol";
import {LibidFactory} from "../LibidFactory.sol";
import {Ping, Pong} from "./Create3.t.sol";

contract LibidFactoryTest is Test {
    LibidFactory internal factory;

    address internal owner = makeAddr("owner");
    address internal stranger = makeAddr("stranger");

    event Deployed(bytes32 indexed nameHash, string name, address addr);

    function setUp() public {
        LibidFactory impl = new LibidFactory();
        factory =
            LibidFactory(address(new ERC1967Proxy(address(impl), abi.encodeCall(LibidFactory.initialize, (owner)))));
    }

    // ─── initialize ─────────────────────────────────────────────────

    function test_initialize_setsOwner() public view {
        assertEq(factory.owner(), owner);
    }

    function test_initialize_revertsOnDoubleInit() public {
        vm.expectRevert();
        factory.initialize(stranger);
    }

    function test_rawImplementation_cannotBeInitialized() public {
        LibidFactory impl = new LibidFactory();
        vm.expectRevert();
        impl.initialize(stranger);
    }

    // ─── deploy ─────────────────────────────────────────────────────

    function test_deploy_revertsIfNotOwner() public {
        vm.prank(stranger);
        vm.expectRevert();
        factory.deploy("libid.thing", type(Ping).creationCode);
    }

    function test_deploy_revertsOnEmptyName() public {
        vm.prank(owner);
        vm.expectRevert(LibidFactory.EmptyName.selector);
        factory.deploy("", type(Ping).creationCode);
    }

    function test_deploy_matchesPredictAndRecordsAndEmits() public {
        string memory name = "libid.thing";
        address predicted = factory.predict(name);

        vm.prank(owner);
        vm.expectEmit(true, false, false, true, address(factory));
        emit Deployed(keccak256(bytes(name)), name, predicted);
        address deployed = factory.deploy(name, type(Ping).creationCode);

        assertEq(deployed, predicted);
        assertEq(Ping(deployed).ping(), 1);
        assertEq(factory.deployedAt(name), deployed);
        assertEq(factory.deployments(keccak256(bytes(name))), deployed);
    }

    function test_deploy_revertsOnNameReuse() public {
        vm.startPrank(owner);
        address first = factory.deploy("libid.thing", type(Ping).creationCode);
        vm.expectRevert(abi.encodeWithSelector(LibidFactory.AlreadyDeployed.selector, "libid.thing", first));
        factory.deploy("libid.thing", type(Ping).creationCode);
        vm.stopPrank();
    }

    /// The address is a function of the name only: rewind the chain and
    /// deploy DIFFERENT code under the same name — the address (and the
    /// prediction made before either deploy) does not move.
    function test_deploy_addressDependsOnNameNotCode() public {
        string memory name = "libid.stable.address";
        address predicted = factory.predict(name);

        uint256 snapshot = vm.snapshotState();
        vm.prank(owner);
        assertEq(factory.deploy(name, type(Ping).creationCode), predicted);

        vm.revertToState(snapshot);
        assertEq(factory.predict(name), predicted);
        vm.prank(owner);
        assertEq(factory.deploy(name, abi.encodePacked(type(Pong).creationCode, abi.encode(uint256(7)))), predicted);
        assertEq(Pong(predicted).stored(), 7);
    }

    function test_predict_matchesActualForSeveralNames() public {
        string[3] memory names = ["libid.NotaryService", "libid.IdentityNames", "libid.GoogleJwtRoots"];
        for (uint256 i = 0; i < names.length; i++) {
            address predicted = factory.predict(names[i]);
            vm.prank(owner);
            assertEq(factory.deploy(names[i], type(Ping).creationCode), predicted, names[i]);
        }
    }

    function test_predict_worksBeforeAnyDeploy() public view {
        assertEq(
            factory.predict("libid.never.deployed"),
            Create3.addressOf(keccak256("libid.never.deployed"), address(factory))
        );
        assertEq(factory.deployedAt("libid.never.deployed"), address(0));
    }

    // ─── a real protocol proxy through the factory ──────────────────

    /// The intended use: deploy an ERC1967 PROXY through the factory
    /// (creationCode = proxy creation code ++ abi.encode(impl, initData));
    /// the proxied contract works and lives at the name's address.
    function test_deploy_notaryServiceProxyThroughFactory() public {
        address signer = makeAddr("notarySigner");
        NotaryService notaryImpl = new NotaryService();
        bytes memory creationCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(notaryImpl), abi.encodeCall(NotaryService.initialize, (owner, signer, 7)))
        );

        address predicted = factory.predict("libid.NotaryService");
        vm.prank(owner);
        address deployed = factory.deploy("libid.NotaryService", creationCode);
        assertEq(deployed, predicted);

        NotaryService notary = NotaryService(deployed);
        assertEq(notary.owner(), owner);
        assertTrue(notary.isTrustedNotary(signer));
        assertEq(notary.fee(), 7);

        // …and it upgrades in place like any other proxy in the stack.
        NotaryService newImpl = new NotaryService();
        vm.prank(owner);
        notary.upgradeToAndCall(address(newImpl), "");
        assertTrue(notary.isTrustedNotary(signer));
        assertEq(notary.fee(), 7);
    }

    // ─── UUPS upgrade of the factory itself ─────────────────────────

    function test_upgrade_revertsIfNotOwner() public {
        LibidFactory newImpl = new LibidFactory();
        vm.prank(stranger);
        vm.expectRevert();
        factory.upgradeToAndCall(address(newImpl), "");
    }

    /// Upgrading the factory keeps its address, its records, and — because
    /// CREATE3 addresses hang off the factory address, not its code — every
    /// future prediction.
    function test_upgrade_byOwner_preservesAddressStateAndPredictions() public {
        vm.prank(owner);
        address before = factory.deploy("libid.existing", type(Ping).creationCode);
        address futurePrediction = factory.predict("libid.future");

        LibidFactory newImpl = new LibidFactory();
        vm.prank(owner);
        factory.upgradeToAndCall(address(newImpl), "");

        assertEq(factory.owner(), owner);
        assertEq(factory.deployedAt("libid.existing"), before);
        assertEq(factory.predict("libid.future"), futurePrediction);
        vm.prank(owner);
        assertEq(factory.deploy("libid.future", type(Ping).creationCode), futurePrediction);
    }

    // ─── Ownable2Step ───────────────────────────────────────────────

    function test_ownership_twoStepTransfer() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(owner);
        factory.transferOwnership(newOwner);
        assertEq(factory.owner(), owner);
        assertEq(factory.pendingOwner(), newOwner);

        vm.prank(newOwner);
        factory.acceptOwnership();
        assertEq(factory.owner(), newOwner);
    }

    function test_renounceOwnership_isDisabled() public {
        vm.prank(owner);
        vm.expectRevert("renounce disabled");
        factory.renounceOwnership();
    }
}
