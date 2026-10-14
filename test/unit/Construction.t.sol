// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {IGuardFactory} from "../../src/interfaces/IGuardFactory.sol";
import {SafeFirewallGuard} from "../../src/SafeFirewallGuard.sol";
import {GuardFactory} from "../../src/GuardFactory.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {ForkSafe} from "../base/ForkSafe.t.sol";

/// @notice I1.4 (constructor immutables) and I1.5 (factory).
abstract contract ConstructionTest is FirewallTestBase {
    GuardFactory internal factory;

    function setUp() public virtual override {
        super.setUp();
        factory = new GuardFactory();
    }

    // ---------------------------------------------------------------- I1.4 constructor

    function test_Constructor_StoresCanonicalAddresses() public view {
        assertEq(guard.SAFE(), address(safe));
        assertEq(guard.MULTISEND_CALL_ONLY(), infra.multiSendCallOnly);
        assertEq(guard.PERMIT2(), infra.permit2);
    }

    function test_Constructor_RevertsOnZeroSafe() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        cfg.safe = address(0);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.ZeroAddress.selector, "safe"));
        new SafeFirewallGuard(cfg);
    }

    function test_Constructor_RevertsOnZeroMultiSendCallOnly() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        cfg.multiSendCallOnly = address(0);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.ZeroAddress.selector, "multiSendCallOnly"));
        new SafeFirewallGuard(cfg);
    }

    function test_Constructor_RevertsOnZeroPermit2() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        cfg.permit2 = address(0);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.ZeroAddress.selector, "permit2"));
        new SafeFirewallGuard(cfg);
    }

    // ---------------------------------------------------------------- I1.5 factory

    function testFuzz_Factory_DeployRevertsUnlessCallerIsSafe(address caller) public {
        vm.assume(caller != address(safe));
        vm.expectRevert(abi.encodeWithSelector(IGuardFactory.NotSafe.selector, caller, address(safe)));
        vm.prank(caller);
        factory.deploy(_config());
    }

    /// @dev The expected address is computed here independently of `predict`, from
    ///      salt = keccak256(abi.encode(safe, VERSION)) and the guard's init code with the config
    ///      as constructor arguments (ADR 0007).
    function test_Factory_DeploysAtPredictedAddress() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        bytes32 salt = keccak256(abi.encode(address(safe), factory.VERSION()));
        bytes32 initCodeHash = keccak256(abi.encodePacked(type(SafeFirewallGuard).creationCode, abi.encode(cfg)));
        address expected = vm.computeCreate2Address(salt, initCodeHash, address(factory));

        assertEq(factory.predict(cfg), expected, "predict");
        vm.prank(address(safe));
        assertEq(factory.deploy(cfg), expected, "deploy");
        assertGt(expected.code.length, 0, "no code at predicted address");
    }

    function testFuzz_Factory_DifferentConfigDifferentAddress(address otherPermit2) public view {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        vm.assume(otherPermit2 != address(0) && otherPermit2 != cfg.permit2);
        ISafeFirewallGuard.FirewallConfig memory other = _config();
        other.permit2 = otherPermit2;
        assertTrue(factory.predict(cfg) != factory.predict(other));
    }

    function test_Factory_GuardBoundToSafe() public {
        vm.prank(address(safe));
        address deployed = factory.deploy(_config());
        assertEq(ISafeFirewallGuard(deployed).SAFE(), address(safe));
    }

    function test_Factory_EmitsGuardDeployed() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        address expected = factory.predict(cfg);
        vm.expectEmit(true, true, true, true, address(factory));
        emit IGuardFactory.GuardDeployed(address(safe), expected, keccak256(abi.encode(cfg)));
        vm.prank(address(safe));
        factory.deploy(cfg);
    }

    /// @dev The realistic path: the Safe itself calls the factory in a signed transaction, as the
    ///      install batch does (deployment notes, step 2.0).
    function test_Factory_DeployFromSafeTransaction() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        address expected = factory.predict(cfg);
        // The installed Phase 1 guard allows ordinary calls (I1.11).
        assertTrue(_execSigned(address(factory), 0, abi.encodeCall(GuardFactory.deploy, (cfg)), Enum.Operation.Call));
        assertGt(expected.code.length, 0);
    }

    /// @dev No "one per Safe" rule (ADR 0007). The same config twice collides at the CREATE2 address.
    function test_Factory_SameConfigTwiceReverts() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        vm.startPrank(address(safe));
        factory.deploy(cfg);
        vm.expectRevert();
        factory.deploy(cfg);
        vm.stopPrank();
    }
}

contract ConstructionUnitTest is ConstructionTest, LocalSafe {
    function setUp() public override(ConstructionTest, FirewallTestBase) {
        ConstructionTest.setUp();
    }
}

contract ConstructionForkTest is ConstructionTest, ForkSafe {
    function setUp() public override(ConstructionTest, FirewallTestBase) {
        ConstructionTest.setUp();
    }
}
