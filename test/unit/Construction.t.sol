// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {IGuardFactory} from "../../src/interfaces/IGuardFactory.sol";
import {SafeFirewallGuard} from "../../src/SafeFirewallGuard.sol";
import {GuardFactory} from "../../src/GuardFactory.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";

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

    /// @dev Permissionless and caller-independent (ADR 0007). A reference deployment by this test
    ///      contract is recorded, then the state is rewound so the fuzzed caller deploys from the same
    ///      starting point. Address, runtime code and bound Safe must all be identical.
    function testFuzz_Factory_AnyoneCanDeploy(address caller) public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();

        uint256 snapshot = vm.snapshotState();
        address refGuard = factory.deploy(cfg);
        bytes32 refCodehash = refGuard.codehash;
        vm.revertToState(snapshot);
        assertEq(refGuard.code.length, 0, "rewind failed");

        vm.prank(caller);
        address deployed = factory.deploy(cfg);

        assertEq(deployed, refGuard, "address depends on caller");
        assertEq(deployed.codehash, refCodehash, "runtime code depends on caller");
        assertEq(ISafeFirewallGuard(deployed).SAFE(), address(safe), "bound Safe depends on caller");
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

    /// @dev A third party front-runs with the identical config. Calls from the Safe, as in the
    ///      install batch's first step, must still succeed, return the pre-deployed guard, and emit
    ///      no GuardDeployed. Phase 9 repeats this against the full batch.
    ///      The signed path can't surface the return value: `execute` calls with output size 0
    ///      (Executor.sol:39) and `execTransaction` returns only `bool` (Safe.sol:126). So the
    ///      signed leg checks success and the absence of the event, and the module leg, which
    ///      copies return data (ModuleManager.sol:168-191), checks the returned address.
    function test_Factory_ThirdPartyPreDeployDoesNotBreakSafeDeploy() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        vm.prank(makeAddr("frontRunner"));
        address preDeployed = factory.deploy(cfg);
        bytes memory deployCall = abi.encodeCall(GuardFactory.deploy, (cfg));

        // Signed leg: succeeds and emits no GuardDeployed.
        vm.recordLogs();
        assertTrue(_execSigned(address(factory), 0, deployCall, Enum.Operation.Call), "signed deploy failed");
        assertEq(_countGuardDeployed(vm.getRecordedLogs()), 0, "signed leg emitted GuardDeployed");

        // Module leg: the Safe's call returns the pre-deployed address and emits no GuardDeployed.
        vm.recordLogs();
        (bool ok, bytes memory ret) = module.execReturnData(safe, address(factory), 0, deployCall, Enum.Operation.Call);
        assertTrue(ok, "module deploy failed");
        assertEq(abi.decode(ret, (address)), preDeployed, "Safe's deploy call did not return the pre-deployed guard");
        assertEq(_countGuardDeployed(vm.getRecordedLogs()), 0, "module leg emitted GuardDeployed");
    }

    function _countGuardDeployed(Vm.Log[] memory logs) internal view returns (uint256 n) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].emitter == address(factory) && logs[i].topics.length > 0
                    && logs[i].topics[0] == IGuardFactory.GuardDeployed.selector
            ) {
                n++;
            }
        }
    }
}

contract ConstructionUnitTest is ConstructionTest, LocalSafe {
    function setUp() public override(ConstructionTest, FirewallTestBase) {
        ConstructionTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract ConstructionForkTest is ConstructionTest, FeatureForkSafe {
    function setUp() public override(ConstructionTest, FirewallTestBase) {
        ConstructionTest.setUp();
    }
}
