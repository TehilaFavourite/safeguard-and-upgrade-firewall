// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {SafeFirewallGuard} from "../../src/SafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {TimelockTestBase} from "../base/TimelockTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";

/// @notice I4.14-I4.17 and D5: the cancel-only guardian (ADR 0008, ADR 0023).
abstract contract GuardianTest is TimelockTestBase {
    function _configItem() internal returns (bytes32) {
        return guard.exposedQueue(ISafeFirewallGuard.ItemKind.CONFIG, keccak256("cap:token"), hex"01");
    }

    function _executeGuardianChange(bytes32 id) internal returns (bool) {
        return _execSigned(
            address(guard), 0, abi.encodeCall(ISafeFirewallGuard.executeGuardianChange, (id)), Enum.Operation.Call
        );
    }

    // ---------------------------------------------------------------- D5 construction

    function test_Guardian_StoredAtConstruction() public view {
        assertEq(guard.guardian(), guardianAddr);
    }

    function test_Guardian_ZeroRejectedAtConstruction() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        cfg.guardian = address(0);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.InvalidGuardian.selector, address(0)));
        new SafeFirewallGuard(cfg);
    }

    /// @dev guardian == the guard itself: the CREATE address is predictable from this contract's nonce.
    function test_Guardian_SelfRejectedAtConstruction() public {
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        cfg.guardian = predicted;
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.InvalidGuardian.selector, predicted));
        new SafeFirewallGuard(cfg);
    }

    // ---------------------------------------------------------------- I4.14 cancel only

    function test_Guardian_CancelsConfigItem() public {
        bytes32 id = _configItem();
        vm.expectEmit(true, true, true, false, address(guard));
        emit ISafeFirewallGuard.Cancelled(id, ISafeFirewallGuard.ItemKind.CONFIG, guardianAddr);
        vm.prank(guardianAddr);
        guard.guardianCancel(id);
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.CANCELLED));
    }

    function testFuzz_Guardian_NonGuardianCannotCancel(address caller) public {
        vm.assume(caller != guardianAddr);
        bytes32 id = _configItem();
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotGuardian.selector, caller));
        vm.prank(caller);
        guard.guardianCancel(id);
    }

    function test_Guardian_CannotQueueOrExecute() public {
        vm.startPrank(guardianAddr);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, guardianAddr));
        guard.queueGuardianChange(_eoa("x"));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, guardianAddr));
        guard.queueEscape(address(0), bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, guardianAddr));
        guard.executeGuardianChange(bytes32(0));
        vm.stopPrank();
    }

    // ---------------------------------------------------------------- I4.15 what the guardian can't cancel

    function test_Guardian_CannotCancelEscapeItem() public {
        bytes32 id = _queueEscape(address(0), bytes32(0));
        vm.expectRevert(
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardianCannotCancel.selector, id, ISafeFirewallGuard.ItemKind.ESCAPE
            )
        );
        vm.prank(guardianAddr);
        guard.guardianCancel(id);
    }

    function test_Guardian_CannotCancelGuardianChange() public {
        bytes32 id = _queueGuardianChange(_eoa("newGuardian"));
        vm.expectRevert(
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardianCannotCancel.selector, id, ISafeFirewallGuard.ItemKind.GUARDIAN_CHANGE
            )
        );
        vm.prank(guardianAddr);
        guard.guardianCancel(id);
    }

    // ---------------------------------------------------------------- I4.16 signers cancel everything

    function test_Signers_CancelGuardianChange() public {
        bytes32 id = _queueGuardianChange(_eoa("newGuardian"));
        assertTrue(_execSigned(address(guard), 0, abi.encodeCall(ISafeFirewallGuard.cancel, (id)), Enum.Operation.Call));
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.CANCELLED));
    }

    function test_Signers_CancelConfigItem() public {
        bytes32 id = _configItem();
        assertTrue(_execSigned(address(guard), 0, abi.encodeCall(ISafeFirewallGuard.cancel, (id)), Enum.Operation.Call));
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.CANCELLED));
    }

    // ---------------------------------------------------------------- D5 guardian-change rules

    function test_GuardianChange_ZeroRejected() public {
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueGuardianChange, (address(0))),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.InvalidGuardian.selector, address(0))
        );
    }

    function test_GuardianChange_SelfRejected() public {
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueGuardianChange, (address(guard))),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.InvalidGuardian.selector, address(guard))
        );
    }

    // ---------------------------------------------------------------- I4.17 replacement

    function test_GuardianChange_OldGuardianLosesRightsImmediately() public {
        address newGuardian = _eoa("newGuardian");
        bytes32 change = _queueGuardianChange(newGuardian);
        bytes32 config = _configItem();
        vm.warp(block.timestamp + GUARDIAN_DELAY);

        vm.expectEmit(true, true, false, false, address(guard));
        emit ISafeFirewallGuard.GuardianChanged(guardianAddr, newGuardian);
        assertTrue(_executeGuardianChange(change));
        assertEq(guard.guardian(), newGuardian);

        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotGuardian.selector, guardianAddr));
        vm.prank(guardianAddr);
        guard.guardianCancel(config);

        vm.prank(newGuardian);
        guard.guardianCancel(config);
        assertEq(uint8(_status(config)), uint8(ISafeFirewallGuard.ItemStatus.CANCELLED));
    }

    /// @dev D2: only the Safe executes, on the signed path.
    function testFuzz_GuardianChange_DirectExecuteReverts(address caller) public {
        vm.assume(caller != address(safe));
        bytes32 id = _queueGuardianChange(_eoa("newGuardian"));
        vm.warp(block.timestamp + GUARDIAN_DELAY);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, caller));
        vm.prank(caller);
        guard.executeGuardianChange(id);
    }

    function test_GuardianChange_WrongKindRejected() public {
        bytes32 id = _configItem();
        vm.warp(block.timestamp + CONFIG_DELAY);
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.executeGuardianChange, (id)),
            Enum.Operation.Call,
            abi.encodeWithSelector(
                ISafeFirewallGuard.WrongItemKind.selector,
                id,
                ISafeFirewallGuard.ItemKind.GUARDIAN_CHANGE,
                ISafeFirewallGuard.ItemKind.CONFIG
            )
        );
    }
}

contract GuardianUnitTest is GuardianTest, LocalSafe {}

/// forge-config: default.fuzz.runs = 64
contract GuardianForkTest is GuardianTest, FeatureForkSafe {}
