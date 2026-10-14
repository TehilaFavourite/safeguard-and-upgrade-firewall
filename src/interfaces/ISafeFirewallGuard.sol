// SPDX-License-Identifier: LGPL-3.0-only
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
        /// @dev The singleton the Safe must run on (ADR 0020, I2.23). It changes only when a
        ///      timelocked migration item executes (ADR 0015).
        address singleton;
        address multiSendCallOnly;
        address permit2;
    }

    /// @notice Which execution path is currently being guarded (ADR 0007).
    enum ExecutionPath {
        NONE,
        SIGNED,
        MODULE
    }

    /// @notice Protected Safe fields compared by the post-check, in comparison order (ADR 0020).
    enum ProtectedField {
        SINGLETON,
        GUARD,
        MODULE_GUARD,
        FALLBACK_HANDLER,
        MODULES,
        OWNERS,
        THRESHOLD
    }

    /// @notice A hook was called by an address other than the bound Safe (ADR 0007).
    error NotSafe(address caller);

    /// @notice A signed transaction set a gas refund field (ADR 0010).
    error RefundNotAllowed(uint256 gasPrice, address gasToken, address refundReceiver);

    /// @notice A signed transaction delegatecalled something other than `MULTISEND_CALL_ONLY` (ADR 0003).
    error DelegateCallNotAllowed(address to);

    /// @notice A module transaction used `DelegateCall`, which is never allowed on the module path.
    error ModuleDelegateCallNotAllowed(address to);

    /// @notice A protected Safe field differs between pre-check and post-check (ADR 0020).
    ///         Encodings:
    ///         - the singleton: `bytes32(uint256(uint160(a)))`, as read from `masterCopy()`;
    ///         - slot-backed fields (guard, module guard, fallback handler): the raw 32-byte slot
    ///           word, which for a clean address equals that same encoding;
    ///         - the module and owner lists: `keccak256(abi.encode(list))`;
    ///         - the threshold: `bytes32(threshold)`.
    error ProtectedStateChanged(ProtectedField field, bytes32 beforeValue, bytes32 afterValue);

    /// @notice The Safe has more than `max` modules, or the module list contains a cycle. The read is
    ///         bounded at `max + 1` entries either way (ADR 0020).
    error TooManyModules(uint256 max);

    /// @notice The module list ended without reaching the sentinel. `next` is where the read stopped (ADR 0020).
    error ModuleListNotTerminated(address next);

    /// @notice The Safe's singleton, read from the proxy's `masterCopy()`, is not the expected one. This
    ///         catches a Safe that was already compromised before this transaction (ADR 0020, I2.23).
    error UnexpectedSingleton(address actual, address expected);

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

    /// @notice The singleton the Safe must be running on (ADR 0020, I2.23).
    function expectedSingleton() external view returns (address);

    /// @notice The only permitted delegatecall target on the signed path (ADR 0003).
    function MULTISEND_CALL_ONLY() external view returns (address);

    /// @notice Permit2, which is never an allowed spender (ADR 0004).
    function PERMIT2() external view returns (address);
}
