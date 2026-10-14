// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {SafeFirewallGuard} from "../../src/SafeFirewallGuard.sol";

/// @notice Test-only subclass. Exposes the transient path flag, which production code keeps
///         internal (invariant I1.8).
contract SafeFirewallGuardHarness is SafeFirewallGuard {
    constructor(FirewallConfig memory config) SafeFirewallGuard(config) {}

    function exposedActivePath() external view returns (ExecutionPath) {
        return _activePath();
    }
}
