// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {ForkSafe} from "../base/ForkSafe.t.sol";
import {PathProbe} from "../mocks/PathProbe.sol";

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

    /// @dev A module pre-hook followed by a signed post-hook. Both calls are pranked as the Safe in
    ///      one test transaction, so the transient path flag carries over between them.
    function test_PostHook_PathMismatchReverts() public {
        vm.prank(address(safe));
        guard.checkModuleTransaction(makeAddr("anyTarget"), 0, "", Enum.Operation.Call, address(module));

        vm.expectRevert(
            abi.encodeWithSelector(
                ISafeFirewallGuard.NoActiveExecution.selector,
                ISafeFirewallGuard.ExecutionPath.SIGNED,
                ISafeFirewallGuard.ExecutionPath.MODULE
            )
        );
        vm.prank(address(safe));
        guard.checkAfterExecution(bytes32(0), true);
    }
}

contract PathAndPostHookUnitTest is PathAndPostHookTest, LocalSafe {
    function setUp() public override(PathAndPostHookTest, FirewallTestBase) {
        PathAndPostHookTest.setUp();
    }
}

contract PathAndPostHookForkTest is PathAndPostHookTest, ForkSafe {
    function setUp() public override(PathAndPostHookTest, FirewallTestBase) {
        PathAndPostHookTest.setUp();
    }
}
