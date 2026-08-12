// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Create3} from "../Create3.sol";

/// The library runs in the caller's context; this harness is "the deployer"
/// whose address feeds the CREATE3 formula.
contract Create3Harness {
    function deploy(bytes32 salt, bytes memory creationCode) external returns (address) {
        return Create3.deploy(salt, creationCode);
    }

    function addressOf(bytes32 salt) external view returns (address) {
        return Create3.addressOf(salt, address(this));
    }
}

contract Ping {
    function ping() external pure returns (uint256) {
        return 1;
    }
}

contract Pong {
    uint256 public immutable stored;

    constructor(uint256 stored_) {
        stored = stored_;
    }
}

contract RevertsInConstructor {
    constructor() {
        revert("nope");
    }
}

contract Create3Test is Test {
    Create3Harness internal harness;

    function setUp() public {
        harness = new Create3Harness();
    }

    function test_deploy_landsOnThePredictedAddress() public {
        bytes32 salt = keccak256("some.salt");
        address predicted = harness.addressOf(salt);

        address deployed = harness.deploy(salt, type(Ping).creationCode);
        assertEq(deployed, predicted);
        assertGt(deployed.code.length, 0);
        assertEq(Ping(deployed).ping(), 1);
    }

    /// The whole point: the address is a function of (deployer, salt) only.
    /// Deploy code X under a salt, rewind the chain, deploy completely
    /// different code (different constructor args and all) under the same
    /// salt — same address.
    function test_deploy_addressIsIndependentOfCreationCode() public {
        bytes32 salt = keccak256("same.salt.either.way");
        address predicted = harness.addressOf(salt);

        uint256 snapshot = vm.snapshotState();
        address withPing = harness.deploy(salt, type(Ping).creationCode);
        assertEq(withPing, predicted);

        vm.revertToState(snapshot);
        address withPong = harness.deploy(salt, abi.encodePacked(type(Pong).creationCode, abi.encode(uint256(42))));
        assertEq(withPong, predicted);
        assertEq(Pong(withPong).stored(), 42);
    }

    function test_deploy_differentSaltsDifferentAddresses() public {
        address a = harness.deploy(keccak256("a"), type(Ping).creationCode);
        address b = harness.deploy(keccak256("b"), type(Ping).creationCode);
        assertNotEq(a, b);
    }

    /// Reusing a salt reruns CREATE2 on an occupied address.
    function test_deploy_revertsOnSaltReuse() public {
        bytes32 salt = keccak256("once");
        harness.deploy(salt, type(Ping).creationCode);
        vm.expectRevert(Create3.ProxyDeployFailed.selector);
        harness.deploy(salt, type(Ping).creationCode);
    }

    function test_deploy_revertsWhenTheConstructorReverts() public {
        vm.expectRevert(Create3.TargetDeployFailed.selector);
        harness.deploy(keccak256("bad"), type(RevertsInConstructor).creationCode);
    }

    /// Empty creation code "succeeds" as a codeless CREATE — refused, since a
    /// deployment that leaves no code behind is never what a caller meant.
    function test_deploy_revertsOnEmptyCreationCode() public {
        vm.expectRevert(Create3.TargetDeployFailed.selector);
        harness.deploy(keccak256("empty"), "");
    }

    /// The two-step formula spelled out, as a guard on the constants.
    function test_addressOf_matchesTheSpelledOutFormula() public view {
        bytes32 salt = keccak256("formula");
        address proxy = address(
            uint160(
                uint256(keccak256(abi.encodePacked(hex"ff", address(harness), salt, keccak256(Create3.PROXY_INITCODE))))
            )
        );
        address expected = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
        assertEq(harness.addressOf(salt), expected);
    }
}
