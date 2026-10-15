// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {IGuardManager} from "safe-smart-account/contracts/interfaces/IGuardManager.sol";
import {IModuleManager} from "safe-smart-account/contracts/interfaces/IModuleManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "./FirewallTestBase.sol";
import {SafeFirewallGuardHarness} from "../harness/SafeFirewallGuardHarness.sol";

/// @notice Helpers for the Phase 4 timelock, escape and guardian suites (ADR 0023).
abstract contract TimelockTestBase is FirewallTestBase {
    uint256 internal constant ESCAPE_DELAY = 72 hours; // ADR 0011
    uint256 internal constant CONFIG_DELAY = 48 hours; // ADR 0011
    uint256 internal constant GUARDIAN_DELAY = 48 hours; // ADR 0011
    uint256 internal constant EXPIRY_WINDOW = 14 days; // ADR 0011

    /// @dev A replacement guard bound to the same Safe, with a different guardian (so a different address).
    function _replacement(string memory label) internal returns (SafeFirewallGuardHarness) {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        cfg.guardian = _eoa(label);
        return new SafeFirewallGuardHarness(cfg);
    }

    /// @dev The id of the single `Queued` event in `logs`.
    function _queuedId(Vm.Log[] memory logs) internal view returns (bytes32 id) {
        uint256 found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].emitter == address(guard) && logs[i].topics.length > 0
                    && logs[i].topics[0] == ISafeFirewallGuard.Queued.selector
            ) {
                id = logs[i].topics[1];
                found++;
            }
        }
        require(found == 1, "expected exactly one Queued event");
    }

    function _queueEscape(address target, bytes32 codehash) internal returns (bytes32 id) {
        vm.recordLogs();
        assertTrue(
            _execSigned(
                address(guard),
                0,
                abi.encodeCall(ISafeFirewallGuard.queueEscape, (target, codehash)),
                Enum.Operation.Call
            ),
            "queueEscape failed"
        );
        id = _queuedId(vm.getRecordedLogs());
    }

    function _queueGuardianChange(address newGuardian) internal returns (bytes32 id) {
        vm.recordLogs();
        assertTrue(
            _execSigned(
                address(guard),
                0,
                abi.encodeCall(ISafeFirewallGuard.queueGuardianChange, (newGuardian)),
                Enum.Operation.Call
            ),
            "queueGuardianChange failed"
        );
        id = _queuedId(vm.getRecordedLogs());
    }

    function _setModuleGuardData(address x) internal pure returns (bytes memory) {
        return abi.encodeCall(IModuleManager.setModuleGuard, (x));
    }

    function _setGuardData(address x) internal pure returns (bytes memory) {
        return abi.encodeCall(IGuardManager.setGuard, (x));
    }

    /// @dev The full replacement, in the enforced order (ADR 0014).
    function _executeEscape(address x) internal {
        assertTrue(_execSigned(address(safe), 0, _setModuleGuardData(x), Enum.Operation.Call), "setModuleGuard step");
        assertTrue(_execSigned(address(safe), 0, _setGuardData(x), Enum.Operation.Call), "setGuard step");
    }

    function _status(bytes32 id) internal view returns (ISafeFirewallGuard.ItemStatus) {
        return guard.getItem(id).status;
    }
}
