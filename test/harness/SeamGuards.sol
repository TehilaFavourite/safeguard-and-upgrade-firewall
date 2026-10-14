// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {SafeFirewallGuardHarness} from "./SafeFirewallGuardHarness.sol";

// Test-only guards that override the two `internal virtual` seams (ADR 0020, D1). Nothing in `src/`
// may override these seams; `script/check-seam-overrides.sh` enforces that.

/// @notice Pre-check only: the protected-state comparison is disabled (Phase 2, I2.19).
contract PreCheckOnlyGuard is SafeFirewallGuardHarness {
    constructor(FirewallConfig memory config) SafeFirewallGuardHarness(config) {}

    function _compareProtectedState() internal view override {}
}

/// @notice Post-check only: the delegatecall/operation policy is disabled (Phase 2, I2.20, I2.13, I2.15).
contract PostCheckOnlyGuard is SafeFirewallGuardHarness {
    constructor(FirewallConfig memory config) SafeFirewallGuardHarness(config) {}

    function _checkOperation(address, Enum.Operation, ExecutionPath) internal view override {}
}

/// @notice Both seams always revert. R2 must still pass (I2.5).
contract PolicyAlwaysRevertsGuard is SafeFirewallGuardHarness {
    error SeamForcedRevert();

    /// @dev Always true. It is an immutable rather than a literal so the compiler can't prove the
    ///      revert is unconditional and flag the guard's code after each seam call as unreachable.
    bool private immutable FORCE_REVERT = true;

    constructor(FirewallConfig memory config) SafeFirewallGuardHarness(config) {}

    function _checkOperation(address, Enum.Operation, ExecutionPath) internal view override {
        if (FORCE_REVERT) revert SeamForcedRevert();
    }

    function _compareProtectedState() internal view override {
        if (FORCE_REVERT) revert SeamForcedRevert();
    }
}

/// @notice Reverts with `CompareRan` whenever the comparison runs, to prove it runs even when the
///         inner call failed (I2.14). A revert marker is used because the seam is `view`, so an
///         override can't record anything.
contract CompareSpyGuard is SafeFirewallGuardHarness {
    error CompareRan();

    /// @dev See `PolicyAlwaysRevertsGuard.FORCE_REVERT`.
    bool private immutable FORCE_REVERT = true;

    constructor(FirewallConfig memory config) SafeFirewallGuardHarness(config) {}

    function _compareProtectedState() internal view override {
        if (FORCE_REVERT) revert CompareRan();
    }
}
