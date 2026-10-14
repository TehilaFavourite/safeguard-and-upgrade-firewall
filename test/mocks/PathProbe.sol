// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {SafeFirewallGuardHarness} from "../harness/SafeFirewallGuardHarness.sol";

/// @notice Called by the Safe during a guarded execution. Records the guard's active path as seen
///         mid-execution (invariant I1.8).
contract PathProbe {
    SafeFirewallGuardHarness public immutable GUARD;
    ISafeFirewallGuard.ExecutionPath public observed;
    bool public called;

    constructor(SafeFirewallGuardHarness guard_) {
        GUARD = guard_;
    }

    function record() external {
        observed = GUARD.exposedActivePath();
        called = true;
    }
}
