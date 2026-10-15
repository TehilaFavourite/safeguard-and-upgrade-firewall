// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {IModuleGuard} from "safe-smart-account/contracts/base/ModuleManager.sol";
import {IERC165} from "safe-smart-account/contracts/interfaces/IERC165.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "./interfaces/ISafeFirewallGuard.sol";
import {SafeSlots} from "./libraries/SafeSlots.sol";
import {MultiSendDecoder} from "./libraries/MultiSendDecoder.sol";

/// @title SafeFirewallGuard
/// @notice Transaction guard and module guard bound to a single Safe v1.5.0 (ADR 0001, ADR 0007).
/// @dev Phase 3 scope: the hook prefix, the refund ban, R2 cancellation, calls to the guard, the
///      expected-singleton check, the delegatecall policy, strict MultiSendCallOnly batch decoding with
///      per-entry policy, and the protected-state snapshot/compare.
///      ⚠️ Not deployable before Phase 10: the allowlist, timelock and caps are not yet in place
///      (docs/build-plan.md).
///      Not upgradeable. Replacement happens only through the escape path (ADR 0014).
contract SafeFirewallGuard is ISafeFirewallGuard {
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override SAFE;
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override MULTISEND_CALL_ONLY;
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override PERMIT2;

    /// @dev Phase 1 returns no module transaction hash, and ADR 0019 rejects using one.
    bytes32 private constant NO_MODULE_TX_HASH = bytes32(0);

    /// @dev The singleton the Safe must run on (I2.23). Storage, not immutable: a timelocked
    ///      migration item (ADR 0015, Phase 8) is the only thing that will update it.
    address private _expectedSingleton;

    /// @dev The execution currently being guarded. `NONE` means no execution is active, so this
    ///      one variable is both the reentrancy flag and the path record (ADR 0005, ADR 0007).
    ExecutionPath private transient _path;
    /// @dev Set by the exact R2 cancellation; makes the post-hook skip the comparison (ADR 0020, D2).
    bool private transient _cancellation;

    // Pre-check snapshot of the protected fields (ADR 0020). The singleton needs no snapshot: the
    // pre-hook has already required it to equal `_expectedSingleton`.
    bytes32 private transient _snapGuard;
    bytes32 private transient _snapModuleGuard;
    bytes32 private transient _snapFallbackHandler;
    bytes32 private transient _snapModulesHash;
    bytes32 private transient _snapOwnersHash;
    uint256 private transient _snapThreshold;

    /// @param config Full configuration. All of it is passed here (there is no initializer), so the
    ///        CREATE2 address commits to the config (ADR 0007).
    constructor(FirewallConfig memory config) {
        if (config.safe == address(0)) revert ZeroAddress("safe");
        if (config.singleton == address(0)) revert ZeroAddress("singleton");
        if (config.multiSendCallOnly == address(0)) revert ZeroAddress("multiSendCallOnly");
        if (config.permit2 == address(0)) revert ZeroAddress("permit2");
        SAFE = config.safe;
        MULTISEND_CALL_ONLY = config.multiSendCallOnly;
        PERMIT2 = config.permit2;
        _expectedSingleton = config.singleton;
    }

    // ------------------------------------------------------------------------- transaction guard

    /// @notice Pre-check for `Safe.execTransaction`, called after signature verification
    ///         (lib/safe-smart-account/contracts/Safe.sol:147-152).
    /// @dev Order follows ADR 0014 (amended by ADR 0020):
    ///      (1) caller check → (2) reentrancy → (3) path → (4) refund fields → (5) R1 escape →
    ///      (6) R2 cancellation → (7) reject other calls to GUARD → (8) expected singleton →
    ///      (9) protected-state snapshot → (10) policy pipeline.
    ///      Phase 2 implements every step except 5 (Phase 4).
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256,
        uint256,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory,
        address
    ) external override {
        _enter(ExecutionPath.SIGNED); // steps 1-3
        _requireNoRefund(gasPrice, gasToken, refundReceiver); // step 4 (ADR 0010)
        // Step 5, R1 escape (Phase 4), goes here: queueEscape / cancelEscape / matched setModuleGuard /
        // setGuard. Escape calls are calls to GUARD, so they must be matched before step 7.
        if (_isCancellation(to, value, data, operation)) {
            _cancellation = true; // step 6 (threat model R2; ADR 0020 D2)
            return;
        }
        _rejectCallToGuard(to, data); // step 7 (ADR 0018)
        _requireExpectedSingleton(); // step 8 (ADR 0020, I2.23)
        _snapshotProtectedState(); // step 9 (ADR 0020)
        _checkOperation(to, operation, ExecutionPath.SIGNED); // step 10, policy pipeline (ADR 0003)
        _checkBatch(to, value, data, operation); // step 10, each inner call of a batch (ADR 0003)
    }

    /// @notice Post-check for `Safe.execTransaction`, called on the guard address cached before
    ///         execution (Safe.sol:149, 203-204; ADR 0001).
    /// @dev Pairing first (ADR 0018), then either the R2 skip or the protected-state comparison,
    ///      which runs whether or not the inner call succeeded (I2.14).
    function checkAfterExecution(bytes32, bool) external override {
        _exit(ExecutionPath.SIGNED);
        if (_cancellation) {
            _cancellation = false; // the marker lives only for this execution (ADR 0020, D2)
            return;
        }
        _compareProtectedState();
        _clearSnapshot();
    }

    // ------------------------------------------------------------------------------ module guard

    /// @notice Pre-check for `execTransactionFromModule*`, called before execution
    ///         (lib/safe-smart-account/contracts/base/ModuleManager.sol:106-108).
    /// @dev Module-path order: (1-3) prefix → (7) reject calls to GUARD → (8) expected singleton →
    ///      (9) snapshot → (10) pipeline. There is no step 4 (the module path has no refunds; ADR 0010)
    ///      and no step 6. Escape and config calls are rejected, not fast-returned, so step 7 covers
    ///      them (ADR 0014). The returned hash is unused (ADR 0019).
    /// @return `NO_MODULE_TX_HASH`.
    function checkModuleTransaction(address to, uint256, bytes memory data, Enum.Operation operation, address)
        external
        override
        returns (bytes32)
    {
        _enter(ExecutionPath.MODULE); // steps 1-3
        _rejectCallToGuard(to, data); // step 7 (ADR 0018)
        _requireExpectedSingleton(); // step 8 (ADR 0020, I2.23)
        _snapshotProtectedState(); // step 9 (ADR 0020)
        _checkOperation(to, operation, ExecutionPath.MODULE); // step 10 (threat model §3.3)
        return NO_MODULE_TX_HASH;
    }

    /// @notice Post-check for `execTransactionFromModule*` (ModuleManager.sol:118-124).
    /// @dev Pairing first (ADR 0018), then the protected-state comparison (ADR 0001, I2.16).
    function checkAfterModuleExecution(bytes32, bool) external override {
        _exit(ExecutionPath.MODULE);
        _compareProtectedState();
        _clearSnapshot();
    }

    // ------------------------------------------------------------------------------------- views

    /// @inheritdoc ISafeFirewallGuard
    function expectedSingleton() external view override returns (address) {
        return _expectedSingleton;
    }

    /// @notice True for `ITransactionGuard`, `IModuleGuard` and `IERC165`. The Safe checks the
    ///         first two in `setGuard` / `setModuleGuard` (GuardManager.sol:72, ModuleManager.sol:259).
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(ITransactionGuard).interfaceId || interfaceId == type(IModuleGuard).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    // ------------------------------------------------------------------------- seams (ADR 0020 D1)

    /// @dev Policy step 10: the delegatecall rule. On the signed path a DelegateCall may only target
    ///      MULTISEND_CALL_ONLY (ADR 0003). On the module path it is never allowed (threat model §3.3).
    ///      `internal virtual` only so test subclasses can disable it. Nothing in `src/` may override
    ///      it (script/check-seam-overrides.sh).
    function _checkOperation(address to, Enum.Operation operation, ExecutionPath path) internal view virtual {
        if (operation != Enum.Operation.DelegateCall) return;
        if (path == ExecutionPath.MODULE) revert ModuleDelegateCallNotAllowed(to);
        if (to != MULTISEND_CALL_ONLY) revert DelegateCallNotAllowed(to);
    }

    /// @dev Post-check comparison (ADR 0020). The singleton is read first, through the proxy's own
    ///      `masterCopy()`. The other fields are read through the Safe's getters only after that,
    ///      because before it the code answering them may be an attacker's.
    ///      `internal virtual` only so test subclasses can disable it. Nothing in `src/` may override
    ///      it (script/check-seam-overrides.sh).
    function _compareProtectedState() internal view virtual {
        _requireUnchanged(ProtectedField.SINGLETON, _word(_expectedSingleton), _word(SafeSlots.masterCopy(SAFE)));
        _requireUnchanged(ProtectedField.GUARD, _snapGuard, SafeSlots.word(SAFE, SafeSlots.GUARD_SLOT));
        _requireUnchanged(
            ProtectedField.MODULE_GUARD, _snapModuleGuard, SafeSlots.word(SAFE, SafeSlots.MODULE_GUARD_SLOT)
        );
        _requireUnchanged(
            ProtectedField.FALLBACK_HANDLER, _snapFallbackHandler, SafeSlots.word(SAFE, SafeSlots.FALLBACK_HANDLER_SLOT)
        );
        _requireUnchanged(ProtectedField.MODULES, _snapModulesHash, SafeSlots.modulesHash(SAFE));
        _requireUnchanged(ProtectedField.OWNERS, _snapOwnersHash, SafeSlots.ownersHash(SAFE));
        _requireUnchanged(ProtectedField.THRESHOLD, bytes32(_snapThreshold), bytes32(SafeSlots.threshold(SAFE)));
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

    /// @dev Step 4 (ADR 0010): all three refund fields must be zero. `handlePayment` runs only when
    ///      gasPrice > 0 (Safe.sol:196); gasToken and refundReceiver are banned as well, so the rule
    ///      reads simply.
    function _requireNoRefund(uint256 gasPrice, address gasToken, address refundReceiver) private pure {
        if (gasPrice != 0 || gasToken != address(0) || refundReceiver != address(0)) {
            revert RefundNotAllowed(gasPrice, gasToken, refundReceiver);
        }
    }

    /// @dev Step 10 for batches (ADR 0003). Applies only to a DelegateCall to MULTISEND_CALL_ONLY, the
    ///      only delegatecall `_checkOperation` lets through on the signed path:
    ///      - the outer value must be zero (D2);
    ///      - the batch is decoded strictly;
    ///      - each inner call goes through the same per-call policy as a top-level Call.
    ///      There are no fast paths for entries: R1 and R2 apply only to top-level transactions, so a
    ///      batch always gets the post-check.
    function _checkBatch(address to, uint256 value, bytes memory data, Enum.Operation operation) private view {
        if (operation != Enum.Operation.DelegateCall || to != MULTISEND_CALL_ONLY) return;
        if (value != 0) revert DelegateCallValueNotZero(value);

        MultiSendDecoder.Entry[] memory entries = MultiSendDecoder.decode(data, SAFE);
        for (uint256 i = 0; i < entries.length; i++) {
            address inner = entries[i].to;
            if (inner == address(this)) revert GuardCallRejected(MultiSendDecoder.selectorOf(data, entries[i]));
            if (inner == MULTISEND_CALL_ONLY) revert NestedBatchNotAllowed(i);
        }
    }

    /// @dev Step 6 (threat model R2): exactly a Call to the Safe itself, value 0 and empty data. The
    ///      refund fields were already required to be zero at step 4.
    function _isCancellation(address to, uint256 value, bytes memory data, Enum.Operation operation)
        private
        view
        returns (bool)
    {
        return to == SAFE && value == 0 && data.length == 0 && operation == Enum.Operation.Call;
    }

    /// @dev Step 7 (ADR 0018): a Safe call to the guard is rejected unless its selector is a permitted
    ///      config or escape function. Phase 2 has none, so every call to the guard is rejected,
    ///      whatever the operation. Calldata shorter than 4 bytes reports a zero-padded selector.
    function _rejectCallToGuard(address to, bytes memory data) private view {
        // forge-lint: disable-next-line(unsafe-typecast)
        if (to == address(this)) revert GuardCallRejected(bytes4(data)); // intended: first 4 bytes = selector
    }

    /// @dev Step 8 (ADR 0020, I2.23): catches a Safe that was already compromised before this
    ///      transaction. The comparison only catches changes made during it.
    function _requireExpectedSingleton() private view {
        address actual = SafeSlots.masterCopy(SAFE);
        address expected = _expectedSingleton;
        if (actual != expected) revert UnexpectedSingleton(actual, expected);
    }

    /// @dev Step 9 (ADR 0020). Safe to read through the Safe's getters: step 8 has just confirmed the
    ///      singleton.
    function _snapshotProtectedState() private {
        _snapGuard = SafeSlots.word(SAFE, SafeSlots.GUARD_SLOT);
        _snapModuleGuard = SafeSlots.word(SAFE, SafeSlots.MODULE_GUARD_SLOT);
        _snapFallbackHandler = SafeSlots.word(SAFE, SafeSlots.FALLBACK_HANDLER_SLOT);
        _snapModulesHash = SafeSlots.modulesHash(SAFE);
        _snapOwnersHash = SafeSlots.ownersHash(SAFE);
        _snapThreshold = SafeSlots.threshold(SAFE);
    }

    /// @dev Post-hook step 4 (build plan): clear transient state once it has been compared.
    function _clearSnapshot() private {
        _snapGuard = bytes32(0);
        _snapModuleGuard = bytes32(0);
        _snapFallbackHandler = bytes32(0);
        _snapModulesHash = bytes32(0);
        _snapOwnersHash = bytes32(0);
        _snapThreshold = 0;
    }

    function _requireUnchanged(ProtectedField field, bytes32 beforeValue, bytes32 afterValue) private pure {
        if (beforeValue != afterValue) revert ProtectedStateChanged(field, beforeValue, afterValue);
    }

    function _word(address a) private pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /// @dev Exposed only through the test harness (invariant I1.8). No production getter.
    function _activePath() internal view returns (ExecutionPath) {
        return _path;
    }
}
