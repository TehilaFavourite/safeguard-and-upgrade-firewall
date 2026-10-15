// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {SafeFirewallGuard} from "../../src/SafeFirewallGuard.sol";

/// @notice Test-only subclass. Exposes internals that production code keeps internal:
///         - the transient path flag (invariant I1.8);
///         - the generic queue, the key-epoch advance and the executability check (Phase 4). Real
///           CONFIG items and key reductions arrive in Phases 6-8, so these let Phase 4 test the
///           mechanism itself (ADR 0023, D6).
contract SafeFirewallGuardHarness is SafeFirewallGuard {
    constructor(FirewallConfig memory config) SafeFirewallGuard(config) {}

    function exposedActivePath() external view returns (ExecutionPath) {
        return _activePath();
    }

    function exposedQueue(ItemKind kind, bytes32 key, bytes calldata payload) external returns (bytes32) {
        return _queue(kind, key, payload);
    }

    function exposedAdvanceKeyEpoch(bytes32 key) external {
        _advanceKeyEpoch(key);
    }

    function exposedRequireExecutable(bytes32 id) external view {
        _requireExecutable(id);
    }
}
