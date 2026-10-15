// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {TimelockTestBase} from "../base/TimelockTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";

/// @notice I4.1-I4.5, D1, D4, I4.18 (ADR 0023). The guardian-change item is the real end-to-end
///         executor in Phase 4. Generic CONFIG items are queued through the test harness, because
///         their executors arrive in Phases 6-7.
abstract contract TimelockTest is TimelockTestBase {
    address internal newGuardian;

    function setUp() public virtual override {
        super.setUp();
        newGuardian = _eoa("newGuardian");
    }

    function _executeGuardianChange(bytes32 id) internal returns (bool) {
        return _execSigned(
            address(guard), 0, abi.encodeCall(ISafeFirewallGuard.executeGuardianChange, (id)), Enum.Operation.Call
        );
    }

    function _executeGuardianChangeExpectRevert(bytes32 id, bytes memory err) internal {
        _execSignedExpectRevert(
            address(guard), 0, abi.encodeCall(ISafeFirewallGuard.executeGuardianChange, (id)), Enum.Operation.Call, err
        );
    }

    // ---------------------------------------------------------------- I4.1 who can queue

    function testFuzz_Queue_DirectCallFromNonSafeReverts(address caller) public {
        vm.assume(caller != address(safe));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, caller));
        vm.prank(caller);
        guard.queueGuardianChange(newGuardian);
    }

    /// @dev The Safe calling outside any guarded execution: the path is NONE.
    function test_Queue_SafeOutsideSignedExecutionReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(ISafeFirewallGuard.NotSignedPath.selector, ISafeFirewallGuard.ExecutionPath.NONE)
        );
        vm.prank(address(safe));
        guard.queueGuardianChange(newGuardian);
    }

    /// @dev The module path is rejected at step 7 (ADR 0014: no config calls on the module path).
    function test_Queue_ModulePathRejected() public {
        bytes memory data = abi.encodeCall(ISafeFirewallGuard.queueGuardianChange, (newGuardian));
        vm.expectRevert(
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardCallRejected.selector, ISafeFirewallGuard.queueGuardianChange.selector
            )
        );
        module.exec(safe, address(guard), 0, data, Enum.Operation.Call);
    }

    // ---------------------------------------------------------------- I4.2 ETA and delays

    function test_Delays_Constants() public view {
        assertEq(guard.ESCAPE_DELAY(), ESCAPE_DELAY);
        assertEq(guard.CONFIG_DELAY(), CONFIG_DELAY);
        assertEq(guard.GUARDIAN_DELAY(), GUARDIAN_DELAY);
        assertEq(guard.EXPIRY_WINDOW(), EXPIRY_WINDOW);
    }

    function test_Queue_GuardianChangeEtaAndEvent() public {
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 eta = uint64(block.timestamp + GUARDIAN_DELAY); // timestamps fit in uint64
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 expiresAt = uint64(eta + EXPIRY_WINDOW); // timestamps fit in uint64
        vm.recordLogs();
        _execSigned(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueGuardianChange, (newGuardian)),
            Enum.Operation.Call
        );
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 id = _queuedId(logs);

        ISafeFirewallGuard.Item memory item = guard.getItem(id);
        assertEq(uint8(item.kind), uint8(ISafeFirewallGuard.ItemKind.GUARDIAN_CHANGE), "kind");
        assertEq(uint8(item.status), uint8(ISafeFirewallGuard.ItemStatus.QUEUED), "status");
        assertEq(item.eta, eta, "eta");
        assertEq(item.expiresAt, expiresAt, "expiresAt");

        // The Queued event carries everything the alert bot needs.
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == ISafeFirewallGuard.Queued.selector) {
                assertEq(uint256(logs[i].topics[2]), uint256(ISafeFirewallGuard.ItemKind.GUARDIAN_CHANGE), "topic kind");
                assertEq(logs[i].topics[3], item.key, "topic key");
                (uint64 evEta, uint64 evExpires, bytes memory payload) =
                    abi.decode(logs[i].data, (uint64, uint64, bytes));
                assertEq(evEta, eta);
                assertEq(evExpires, expiresAt);
                assertEq(payload, abi.encode(newGuardian));
            }
        }
    }

    function test_Queue_ConfigItemUsesConfigDelay() public {
        bytes32 id = guard.exposedQueue(ISafeFirewallGuard.ItemKind.CONFIG, keccak256("k"), hex"01");
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(guard.getItem(id).eta, uint64(block.timestamp + CONFIG_DELAY)); // timestamps fit in uint64
    }

    // ---------------------------------------------------------------- I4.3 maturity and expiry boundaries

    function testFuzz_Timelock_MaturityAndExpiryBoundaries(uint256 dt) public {
        bytes32 id = _queueGuardianChange(newGuardian);
        ISafeFirewallGuard.Item memory item = guard.getItem(id);
        dt = bound(dt, 0, GUARDIAN_DELAY + EXPIRY_WINDOW + 1 days);
        vm.warp(block.timestamp + dt);

        if (block.timestamp < item.eta) {
            _executeGuardianChangeExpectRevert(
                id, abi.encodeWithSelector(ISafeFirewallGuard.NotMatured.selector, id, item.eta)
            );
        } else if (block.timestamp >= item.expiresAt) {
            _executeGuardianChangeExpectRevert(
                id, abi.encodeWithSelector(ISafeFirewallGuard.ItemExpired.selector, id, item.expiresAt)
            );
        } else {
            assertTrue(_executeGuardianChange(id));
            assertEq(guard.guardian(), newGuardian);
        }
    }

    function test_Timelock_ExactBoundaries() public {
        bytes32 id = _queueGuardianChange(newGuardian);
        ISafeFirewallGuard.Item memory item = guard.getItem(id);

        vm.warp(item.eta - 1);
        _executeGuardianChangeExpectRevert(
            id, abi.encodeWithSelector(ISafeFirewallGuard.NotMatured.selector, id, item.eta)
        );

        vm.warp(item.expiresAt);
        _executeGuardianChangeExpectRevert(
            id, abi.encodeWithSelector(ISafeFirewallGuard.ItemExpired.selector, id, item.expiresAt)
        );

        vm.warp(item.expiresAt - 1);
        assertTrue(_executeGuardianChange(id), "last executable second");
    }

    // ---------------------------------------------------------------- I4.4 at most once; re-queue (D1)

    function test_Timelock_ExecuteTwiceReverts() public {
        bytes32 id = _queueGuardianChange(newGuardian);
        vm.warp(block.timestamp + GUARDIAN_DELAY);
        assertTrue(_executeGuardianChange(id));
        _executeGuardianChangeExpectRevert(
            id,
            abi.encodeWithSelector(
                ISafeFirewallGuard.ItemNotQueued.selector, id, ISafeFirewallGuard.ItemStatus.EXECUTED
            )
        );
    }

    function test_Timelock_CancelledItemCannotExecute() public {
        bytes32 id = _queueGuardianChange(newGuardian);
        assertTrue(_execSigned(address(guard), 0, abi.encodeCall(ISafeFirewallGuard.cancel, (id)), Enum.Operation.Call));
        vm.warp(block.timestamp + GUARDIAN_DELAY);
        _executeGuardianChangeExpectRevert(
            id,
            abi.encodeWithSelector(
                ISafeFirewallGuard.ItemNotQueued.selector, id, ISafeFirewallGuard.ItemStatus.CANCELLED
            )
        );
    }

    function test_Timelock_ReQueueAfterCancelGetsNewId() public {
        bytes32 first = _queueGuardianChange(newGuardian);
        _execSigned(address(guard), 0, abi.encodeCall(ISafeFirewallGuard.cancel, (first)), Enum.Operation.Call);
        bytes32 second = _queueGuardianChange(newGuardian);
        assertTrue(second != first, "same action re-queued must get a new id (D1)");
        assertEq(uint8(_status(second)), uint8(ISafeFirewallGuard.ItemStatus.QUEUED));
    }

    function test_Timelock_ExpiredCannotExecuteEvenIfNotMarked() public {
        bytes32 id = _queueGuardianChange(newGuardian);
        ISafeFirewallGuard.Item memory item = guard.getItem(id);
        vm.warp(item.expiresAt + 1);
        _executeGuardianChangeExpectRevert(
            id, abi.encodeWithSelector(ISafeFirewallGuard.ItemExpired.selector, id, item.expiresAt)
        );
    }

    // ---------------------------------------------------------------- D4 markExpired

    function test_MarkExpired_BeforeExpiryReverts() public {
        bytes32 id = _queueGuardianChange(newGuardian);
        ISafeFirewallGuard.Item memory item = guard.getItem(id);
        vm.warp(item.expiresAt - 1);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotExpiredYet.selector, id, item.expiresAt));
        guard.markExpired(id);
    }

    function test_MarkExpired_AnyoneAfterExpiryAndIdempotent() public {
        bytes32 id = _queueGuardianChange(newGuardian);
        vm.warp(guard.getItem(id).expiresAt);

        vm.expectEmit(true, true, false, false, address(guard));
        emit ISafeFirewallGuard.Expired(id, ISafeFirewallGuard.ItemKind.GUARDIAN_CHANGE);
        vm.prank(_eoa("anyone"));
        guard.markExpired(id);
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.EXPIRED));

        vm.recordLogs();
        guard.markExpired(id); // idempotent: no revert, no second event
        assertEq(vm.getRecordedLogs().length, 0, "second markExpired emitted");
    }

    function test_MarkExpired_ExecutedItemReverts() public {
        bytes32 id = _queueGuardianChange(newGuardian);
        vm.warp(block.timestamp + GUARDIAN_DELAY);
        _executeGuardianChange(id);
        vm.warp(block.timestamp + EXPIRY_WINDOW);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISafeFirewallGuard.ItemNotQueued.selector, id, ISafeFirewallGuard.ItemStatus.EXECUTED
            )
        );
        guard.markExpired(id);
    }

    // ---------------------------------------------------------------- I4.5 events

    function test_Events_ExecutedAndCancelled() public {
        bytes32 a = _queueGuardianChange(newGuardian);
        vm.warp(block.timestamp + GUARDIAN_DELAY);
        vm.expectEmit(true, true, false, false, address(guard));
        emit ISafeFirewallGuard.Executed(a, ISafeFirewallGuard.ItemKind.GUARDIAN_CHANGE);
        _executeGuardianChange(a);

        bytes32 b = _queueGuardianChange(_eoa("another"));
        vm.expectEmit(true, true, true, false, address(guard));
        emit ISafeFirewallGuard.Cancelled(b, ISafeFirewallGuard.ItemKind.GUARDIAN_CHANGE, address(safe));
        _execSigned(address(guard), 0, abi.encodeCall(ISafeFirewallGuard.cancel, (b)), Enum.Operation.Call);
    }

    // ---------------------------------------------------------------- I4.18 key epochs (D6)

    function test_KeyEpoch_AdvanceSupersedesPendingItemsForThatKeyOnly() public {
        bytes32 keyA = keccak256("cap:tokenA");
        bytes32 keyB = keccak256("cap:tokenB");
        bytes32 a = guard.exposedQueue(ISafeFirewallGuard.ItemKind.CONFIG, keyA, hex"01");
        bytes32 b = guard.exposedQueue(ISafeFirewallGuard.ItemKind.CONFIG, keyB, hex"02");
        vm.warp(block.timestamp + CONFIG_DELAY);

        vm.expectEmit(true, false, false, true, address(guard));
        emit ISafeFirewallGuard.KeyEpochAdvanced(keyA, 1);
        guard.exposedAdvanceKeyEpoch(keyA);
        assertEq(guard.keyEpoch(keyA), 1);

        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.ItemSuperseded.selector, a, 0, 1));
        guard.exposedRequireExecutable(a);
        guard.exposedRequireExecutable(b); // other key unaffected

        bytes32 a2 = guard.exposedQueue(ISafeFirewallGuard.ItemKind.CONFIG, keyA, hex"03");
        vm.warp(block.timestamp + CONFIG_DELAY);
        guard.exposedRequireExecutable(a2); // queued under the new epoch
    }
}

contract TimelockUnitTest is TimelockTest, LocalSafe {
    function setUp() public override(TimelockTest, FirewallTestBase) {
        TimelockTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract TimelockForkTest is TimelockTest, FeatureForkSafe {
    function setUp() public override(TimelockTest, FirewallTestBase) {
        TimelockTest.setUp();
    }
}
