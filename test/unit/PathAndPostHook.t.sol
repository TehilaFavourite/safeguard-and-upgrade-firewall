// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";
import {PathProbe} from "../mocks/PathProbe.sol";
import {Forwarder} from "../mocks/Forwarder.sol";
import {SafeFirewallGuardHarness} from "../harness/SafeFirewallGuardHarness.sol";
import {PostCheckOnlyGuard} from "../harness/SeamGuards.sol";

/// @notice I1.8 (path tracking) and I1.9 (post-hook needs a matching pre-hook; ADR 0018).
abstract contract PathAndPostHookTest is FirewallTestBase {
    PathProbe internal probe;

    function setUp() public virtual override {
        super.setUp();
        probe = new PathProbe(guard);
    }

    // ---------------------------------------------------------------- I1.8 path tracking

    function test_Path_SignedPathRecorded() public {
        _execSigned(address(probe), 0, abi.encodeCall(PathProbe.record, ()), Enum.Operation.Call);
        assertTrue(probe.called(), "probe not reached");
        assertEq(uint8(probe.observed()), uint8(ISafeFirewallGuard.ExecutionPath.SIGNED));
    }

    function test_Path_ModulePathRecorded() public {
        module.exec(safe, address(probe), 0, abi.encodeCall(PathProbe.record, ()), Enum.Operation.Call);
        assertTrue(probe.called(), "probe not reached");
        assertEq(uint8(probe.observed()), uint8(ISafeFirewallGuard.ExecutionPath.MODULE));
    }

    function test_Path_NoneOutsideExecution() public {
        assertEq(uint8(guard.exposedActivePath()), uint8(ISafeFirewallGuard.ExecutionPath.NONE), "before");
        _execSigned(address(probe), 0, abi.encodeCall(PathProbe.record, ()), Enum.Operation.Call);
        assertEq(uint8(guard.exposedActivePath()), uint8(ISafeFirewallGuard.ExecutionPath.NONE), "after");
    }

    // ---------------------------------------------------------------- I1.9 post-hook pairing

    function test_PostHook_SignedWithoutPreHookReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ISafeFirewallGuard.NoActiveExecution.selector,
                ISafeFirewallGuard.ExecutionPath.SIGNED,
                ISafeFirewallGuard.ExecutionPath.NONE
            )
        );
        vm.prank(address(safe));
        guard.checkAfterExecution(bytes32(0), true);
    }

    function test_PostHook_ModuleWithoutPreHookReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ISafeFirewallGuard.NoActiveExecution.selector,
                ISafeFirewallGuard.ExecutionPath.MODULE,
                ISafeFirewallGuard.ExecutionPath.NONE
            )
        );
        vm.prank(address(safe));
        guard.checkAfterModuleExecution(bytes32(0), true);
    }
}

/// @notice I1.9, the mismatch case: a signed post-hook reached while a module execution is active.
/// @dev Transient storage is per transaction, so the mismatch must happen inside one real execution.
///      Two separately pranked hook calls are two top-level calls, and whether transient state carries
///      over between them depends on the forge version (1.5.1 kept it, 1.8.5 resets it).
///      Every real route here is closed earlier on the full guard: step 7 rejects calls to GUARD and
///      the module path rejects delegatecall. So this runs on `PostCheckOnlyGuard` (operation policy
///      off), and pins the pairing check as the defence-in-depth layer behind both.
abstract contract PathMismatchTest is FirewallTestBase {
    Forwarder internal forwarder;

    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        virtual
        override
        returns (SafeFirewallGuardHarness)
    {
        return new PostCheckOnlyGuard(config);
    }

    function setUp() public virtual override {
        super.setUp();
        forwarder = new Forwarder();
    }

    /// @dev Module pre-hook (path = MODULE) → the Safe delegatecalls the forwarder → the forwarder,
    ///      running as the Safe, calls the signed post-hook → it reverts. The Safe returns the revert
    ///      data as a failed module execution; the module's own post-hook then pairs correctly.
    function test_PostHook_PathMismatchReverts() public {
        bytes memory reenter = abi.encodeCall(
            Forwarder.forward,
            (address(guard), abi.encodeCall(ITransactionGuard.checkAfterExecution, (bytes32(0), true)))
        );
        (bool success, bytes memory ret) =
            module.execReturnData(safe, address(forwarder), 0, reenter, Enum.Operation.DelegateCall);
        assertFalse(success, "mismatched post-hook must revert");
        assertEq(
            ret,
            abi.encodeWithSelector(
                ISafeFirewallGuard.NoActiveExecution.selector,
                ISafeFirewallGuard.ExecutionPath.SIGNED,
                ISafeFirewallGuard.ExecutionPath.MODULE
            )
        );
        assertEq(uint8(guard.exposedActivePath()), uint8(ISafeFirewallGuard.ExecutionPath.NONE), "path cleared");
    }
}

contract PathAndPostHookUnitTest is PathAndPostHookTest, LocalSafe {
    function setUp() public override(PathAndPostHookTest, FirewallTestBase) {
        PathAndPostHookTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract PathAndPostHookForkTest is PathAndPostHookTest, FeatureForkSafe {
    function setUp() public override(PathAndPostHookTest, FirewallTestBase) {
        PathAndPostHookTest.setUp();
    }
}

contract PathMismatchUnitTest is PathMismatchTest, LocalSafe {
    function setUp() public override(PathMismatchTest, FirewallTestBase) {
        PathMismatchTest.setUp();
    }

    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(PathMismatchTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return PathMismatchTest._newGuard(config);
    }
}

/// forge-config: default.fuzz.runs = 64
contract PathMismatchForkTest is PathMismatchTest, FeatureForkSafe {
    function setUp() public override(PathMismatchTest, FirewallTestBase) {
        PathMismatchTest.setUp();
    }

    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(PathMismatchTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return PathMismatchTest._newGuard(config);
    }
}
