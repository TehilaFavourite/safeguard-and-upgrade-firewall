// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {IModuleGuard} from "safe-smart-account/contracts/base/ModuleManager.sol";

/// @title ISafeFirewallGuard
/// @notice Transaction guard and module guard for a single Safe v1.5.0 (ADR 0001, ADR 0007).
interface ISafeFirewallGuard is ITransactionGuard, IModuleGuard {
    /// @notice Full guard configuration. Passed to the constructor only; there is no initializer,
    ///         so the CREATE2 address commits to every field (ADR 0007).
    /// @dev Fields are added phase by phase. Phase 1 holds only the bound Safe and the canonical
    ///      addresses (ADR 0013).
    struct FirewallConfig {
        address safe;
        address multiSendCallOnly;
        address permit2;
    }

    /// @notice Which execution path is currently being guarded (ADR 0007).
    enum ExecutionPath {
        NONE,
        SIGNED,
        MODULE
    }

    /// @notice A hook was called by an address other than the bound Safe (ADR 0007).
    error NotSafe(address caller);

    /// @notice A constructor argument that must be non-zero was zero.
    error ZeroAddress(string field);

    /// @notice A pre-hook was entered while another guarded execution was active (ADR 0005).
    error Reentrancy(ExecutionPath active);

    /// @notice A post-hook ran without a matching pre-hook on the same path. Defence in depth only;
    ///         the real control is the `to == GUARD` rule (ADR 0018).
    error NoActiveExecution(ExecutionPath expected, ExecutionPath active);

    /// @notice A Safe call targeted the guard with a selector that is not a permitted config or
    ///         escape function (ADR 0018).
    error GuardCallRejected(bytes4 selector);

    /// @notice The Safe this guard is bound to.
    function SAFE() external view returns (address);

    /// @notice The only permitted delegatecall target on the signed path (ADR 0003).
    function MULTISEND_CALL_ONLY() external view returns (address);

    /// @notice Permit2, which is never an allowed spender (ADR 0004).
    function PERMIT2() external view returns (address);
}
