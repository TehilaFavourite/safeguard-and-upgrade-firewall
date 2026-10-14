// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {IModuleGuard} from "safe-smart-account/contracts/base/ModuleManager.sol";
import {IERC165} from "safe-smart-account/contracts/interfaces/IERC165.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "./interfaces/ISafeFirewallGuard.sol";

/// @title SafeFirewallGuard
/// @notice Transaction guard and module guard bound to a single Safe v1.5.0 (ADR 0001, ADR 0007).
/// @dev Phase 1 scope: caller check, reentrancy flag, path tracking, post-hook pairing, rejection
///      of calls to the guard itself, and ERC-165. Policy is added in later phases. Until then, any
///      call that passes this prefix is allowed (invariant I1.11; test scaffolding only).
///      Not upgradeable. Replacement happens only through the escape path (ADR 0014).
contract SafeFirewallGuard is ISafeFirewallGuard {
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override SAFE;
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override MULTISEND_CALL_ONLY;
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override PERMIT2;

    /// @dev The execution currently being guarded. `NONE` means no execution is active, so this
    ///      one variable is both the reentrancy flag and the path record (ADR 0005, ADR 0007).
    ///      Transient: a revert discards it, and it is empty at the start of every transaction.
    ExecutionPath private transient _path;

    /// @dev Phase 1 returns no module transaction hash; nothing consumes it yet (ModuleManager.sol:120).
    bytes32 private constant NO_MODULE_TX_HASH = bytes32(0);

    /// @param config Full configuration. All of it is passed here (there is no initializer), so the
    ///        CREATE2 address commits to the config (ADR 0007).
    constructor(FirewallConfig memory config) {
        if (config.safe == address(0)) revert ZeroAddress("safe");
        if (config.multiSendCallOnly == address(0)) revert ZeroAddress("multiSendCallOnly");
        if (config.permit2 == address(0)) revert ZeroAddress("permit2");
        SAFE = config.safe;
        MULTISEND_CALL_ONLY = config.multiSendCallOnly;
        PERMIT2 = config.permit2;
    }

    // ------------------------------------------------------------------------- transaction guard

    /// @notice Pre-check for `Safe.execTransaction`, called after signature verification
    ///         (lib/safe-smart-account/contracts/Safe.sol:147-152).
    /// @dev Order follows ADR 0014: (1) caller check → (2) reentrancy → (3) path → (4) refund
    ///      fields → (5) R1 escape → (6) R2 cancellation → (7) reject other calls to GUARD →
    ///      (8) slot snapshot → (9) policy pipeline. Phase 1 implements steps 1-3 and 7.
    function checkTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external override {
        _enter(ExecutionPath.SIGNED); // steps 1-3
        // Steps 4-6 go here, before step 7 (ADR 0014):
        //   4. refund fields zero (Phase 2, ADR 0010);
        //   5. R1 escape: queueEscape / cancelEscape / matched setModuleGuard / setGuard (Phase 4).
        //      Escape calls are calls to GUARD, so they must be matched before step 7;
        //   6. R2 cancellation (Phase 2).
        _rejectCallToGuard(to, data); // step 7 (ADR 0018)
        // Steps 8-9, slot snapshot and policy pipeline, follow here (Phase 2 onwards).
    }

    /// @notice Post-check for `Safe.execTransaction`, called on the guard address cached before
    ///         execution (Safe.sol:149, 203-204; ADR 0001).
    /// @dev Reverts with `NoActiveExecution` unless a signed pre-check is active. Defence in depth:
    ///      the real control against out-of-turn hook calls is `_rejectCallToGuard` (ADR 0018).
    function checkAfterExecution(bytes32, bool) external override {
        _exit(ExecutionPath.SIGNED);
    }

    // ------------------------------------------------------------------------------ module guard

    /// @notice Pre-check for `execTransactionFromModule*`, called before execution
    ///         (lib/safe-smart-account/contracts/base/ModuleManager.sol:106-108).
    /// @dev Same prefix as `checkTransaction`, without refund fields (the module path has no
    ///      refunds; ADR 0010). The returned hash is passed back unchanged to
    ///      `checkAfterModuleExecution` (ModuleManager.sol:120). It is unused in Phase 1.
    /// @return Module transaction hash. `NO_MODULE_TX_HASH` in Phase 1.
    function checkModuleTransaction(address to, uint256, bytes memory data, Enum.Operation, address)
        external
        override
        returns (bytes32)
    {
        _enter(ExecutionPath.MODULE); // steps 1-3
        // No step 4 on the module path (no refunds, ADR 0010). Escape and config calls are rejected,
        // not fast-returned, on this path (ADR 0014), so step 7 covers them; step 6 doesn't apply.
        _rejectCallToGuard(to, data); // step 7 (ADR 0018)
        // Steps 8-9, slot snapshot and policy pipeline, follow here (Phase 2 onwards).
        return NO_MODULE_TX_HASH;
    }

    /// @notice Post-check for `execTransactionFromModule*` (ModuleManager.sol:118-124).
    /// @dev Reverts with `NoActiveExecution` unless a module pre-check is active (ADR 0018).
    function checkAfterModuleExecution(bytes32, bool) external override {
        _exit(ExecutionPath.MODULE);
    }

    // ----------------------------------------------------------------------------------- ERC-165

    /// @notice True for `ITransactionGuard`, `IModuleGuard` and `IERC165`. The Safe checks the
    ///         first two in `setGuard` / `setModuleGuard` (GuardManager.sol:72, ModuleManager.sol:259).
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(ITransactionGuard).interfaceId || interfaceId == type(IModuleGuard).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    // ---------------------------------------------------------------------------------- internal

    /// @dev Hook prefix (ADR 0014, steps 1-3): caller check, then reentrancy, then path.
    function _enter(ExecutionPath path) private {
        if (msg.sender != SAFE) revert NotSafe(msg.sender);
        ExecutionPath active = _path;
        if (active != ExecutionPath.NONE) revert Reentrancy(active);
        _path = path;
    }

    /// @dev Post-hook prefix: caller check, then pairing with the matching pre-hook, then clear.
    function _exit(ExecutionPath path) private {
        if (msg.sender != SAFE) revert NotSafe(msg.sender);
        ExecutionPath active = _path;
        if (active != path) revert NoActiveExecution(path, active);
        _path = ExecutionPath.NONE;
    }

    /// @dev ADR 0018: a Safe call to the guard is rejected unless its selector is a permitted
    ///      config or escape function. Phase 1 has none, so every call to the guard is rejected,
    ///      whatever the operation. Calldata shorter than 4 bytes reports a zero-padded selector.
    function _rejectCallToGuard(address to, bytes memory data) private view {
        if (to == address(this)) revert GuardCallRejected(bytes4(data));
    }

    /// @dev Exposed only through the test harness (invariant I1.8). No production getter.
    function _activePath() internal view returns (ExecutionPath) {
        return _path;
    }
}
