// SPDX-License-Identifier: LGPL-3.0-only
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

    function testFuzz_Factory_AnyoneCanDeploy(address caller) public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        vm.prank(caller);
        address deployed = factory.deploy(cfg);
        assertEq(deployed, factory.predict(cfg));
        assertGt(deployed.code.length, 0);
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
        address deployed = factory.deploy(_config());
        assertEq(ISafeFirewallGuard(deployed).SAFE(), address(safe));
    }

    function test_Factory_EmitsGuardDeployed() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        address expected = factory.predict(cfg);
        vm.expectEmit(true, true, true, true, address(factory));
        emit IGuardFactory.GuardDeployed(address(safe), expected, keccak256(abi.encode(cfg)));
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

    /// @dev Idempotent (ADR 0007): deploying the same config again returns the existing guard
    ///      instead of reverting.
    function test_Factory_DeployTwiceReturnsSameAddress() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        address first = factory.deploy(cfg);
        address second = factory.deploy(cfg);
        assertEq(second, first);
    }

    /// @dev No state change on the second call, so no event (engineering standard: an event per
    ///      state change).
    function test_Factory_SecondDeployEmitsNothing() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        factory.deploy(cfg);
        vm.recordLogs();
        factory.deploy(cfg);
        assertEq(vm.getRecordedLogs().length, 0);
    }

    /// @dev A third party front-runs with the identical config. The Safe's own deploy, the first
    ///      step of the install batch, must still succeed and return the same guard. Phase 9 repeats
    ///      this against the full batch.
    function test_Factory_ThirdPartyPreDeployDoesNotBreakSafeDeploy() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        vm.prank(makeAddr("frontRunner"));
        address preDeployed = factory.deploy(cfg);

        assertTrue(_execSigned(address(factory), 0, abi.encodeCall(GuardFactory.deploy, (cfg)), Enum.Operation.Call));
        assertEq(factory.predict(cfg), preDeployed);
        assertEq(ISafeFirewallGuard(preDeployed).SAFE(), address(safe));
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
