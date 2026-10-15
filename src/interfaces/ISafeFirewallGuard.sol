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
        /// @dev Cancel-only guardian (ADR 0008). Required, never removable, != the guard (ADR 0023, D5).
        address guardian;
    }

    /// @notice Kinds of timelocked items (ADR 0023). Later phases append kinds.
    enum ItemKind {
        ESCAPE, // guard removal or replacement (ADR 0014), 72h
        GUARDIAN_CHANGE, // guardian replacement (ADR 0008), 48h
        CONFIG // guard configuration (Phases 6-7), 48h
    }

    enum ItemStatus {
        NONE,
        QUEUED,
        EXECUTED,
        CANCELLED,
        EXPIRED
    }

    /// @notice A timelocked item. Executable while `eta <= now < expiresAt` and its key epoch is current.
    struct Item {
        ItemKind kind;
        ItemStatus status;
        bytes32 key;
        uint64 eta;
        uint64 expiresAt;
        uint64 keyEpoch;
        bytes32 payloadHash;
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

    // ---- timelock events (ADR 0023): enough for the alert bot to work from events alone ----

    event Queued(
        bytes32 indexed id, ItemKind indexed kind, bytes32 indexed key, uint64 eta, uint64 expiresAt, bytes payload
    );
    event Executed(bytes32 indexed id, ItemKind indexed kind);
    event Cancelled(bytes32 indexed id, ItemKind indexed kind, address indexed by);
    event Expired(bytes32 indexed id, ItemKind indexed kind);
    event KeyEpochAdvanced(bytes32 indexed key, uint64 epoch);
    event GuardianChanged(address indexed previous, address indexed current);

    /// @notice A hook was called by an address other than the bound Safe (ADR 0007).
    error NotSafe(address caller);

    // ---- timelock errors (ADR 0023) ----

    /// @notice A config function was called outside a signed-path execution (ADR 0007, ADR 0023).
    error NotSignedPath(ExecutionPath active);
    error NotGuardian(address caller);
    /// @notice A guardian must be non-zero and not the guard itself (ADR 0023, D5).
    error InvalidGuardian(address guardian);
    error ItemNotQueued(bytes32 id, ItemStatus status);
    error WrongItemKind(bytes32 id, ItemKind expected, ItemKind actual);
    /// @notice Escape items are cancelled with `cancelEscape` (R1), not `cancel`.
    error EscapeRequiresCancelEscape(bytes32 id);
    error NotMatured(bytes32 id, uint64 eta);
    error ItemExpired(bytes32 id, uint64 expiresAt);
    error NotExpiredYet(bytes32 id, uint64 expiresAt);
    /// @notice The item's key epoch is older than the key's current epoch (ADR 0023, D6).
    error ItemSuperseded(bytes32 id, uint64 itemEpoch, uint64 currentEpoch);
    error GuardianCannotCancel(bytes32 id, ItemKind kind);
    error EscapeAlreadyPending(address target, bytes32 id);
    /// @notice I4.20: the escape target isn't a guard bound to this Safe (ADR 0023).
    error EscapeTargetNotBound(address target, address reportedSafe);
    error EscapeCodehashMismatch(address target, bytes32 expected, bytes32 actual);
    /// @notice setGuard(x) before the module guard slot equals x (ADR 0014).
    error EscapeOrderViolation(address target, address moduleGuard);

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

    // ---- MultiSendCallOnly batch decoding (ADR 0003): one accepted encoding per batch ----

    /// @notice The delegatecall to MULTISEND_CALL_ONLY doesn't call `multiSend(bytes)`.
    error MultiSendBadSelector(bytes4 selector);

    /// @notice The `multiSend(bytes)` ABI wrapper isn't canonical: the offset word isn't 0x20, or
    ///         `data.length != 4 + 32 + 32 + ceil32(declaredLength)`.
    error MultiSendNotCanonical(uint256 offsetWord, uint256 declaredLength, uint256 dataLength);

    /// @notice A byte of the ABI padding after the packed transactions isn't zero (ADR 0003, D3).
    error MultiSendPaddingNotZero(uint256 position);

    /// @notice The batch contains no transactions.
    error EmptyBatch();

    /// @notice The entry at `entryOffset` (relative to the packed transactions) doesn't fit: the
    ///         85-byte header or its data runs past the end, so entries don't tile the buffer exactly.
    error MultiSendMalformed(uint256 entryOffset);

    /// @notice Inner entry `index` has an operation byte other than 0 (Call). Byte 1 (DelegateCall) is
    ///         rejected by the guard itself (ADR 0003).
    error InnerOperationNotAllowed(uint256 index, uint8 operation);

    /// @notice The batch has more than `max` inner calls (ADR 0003, D1).
    error TooManyBatchCalls(uint256 max);

    /// @notice Inner entry `index` calls MULTISEND_CALL_ONLY itself (ADR 0003, D4).
    error NestedBatchNotAllowed(uint256 index);

    /// @notice A delegatecall carried a non-zero `value`, which Executor ignores (ADR 0003, D2).
    error DelegateCallValueNotZero(uint256 value);

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

    // ---- timelock (ADR 0002, 0008, 0011, 0014, 0023) ----

    /// @notice Queue guard removal (`target == 0`) or replacement. Signed path, R1 (ADR 0014).
    function queueEscape(address target, bytes32 codehash) external returns (bytes32 id);

    /// @notice Cancel an escape item. Signed path, R1 (ADR 0008, 0014).
    function cancelEscape(bytes32 id) external;

    /// @notice Queue a guardian replacement (48h). Signed path. The guardian can't cancel it.
    function queueGuardianChange(address newGuardian) external returns (bytes32 id);

    /// @notice Execute a matured guardian change. Signed path only (ADR 0023, D2).
    function executeGuardianChange(bytes32 id) external;

    /// @notice Cancel any non-escape item. Signed path.
    function cancel(bytes32 id) external;

    /// @notice Cancel an item. Callable only by the guardian, directly. Not escape or guardian-change items.
    function guardianCancel(bytes32 id) external;

    /// @notice Mark an item expired. Anyone; only after expiry; a no-op if already expired (ADR 0023, D4).
    function markExpired(bytes32 id) external;

    function guardian() external view returns (address);

    function getItem(bytes32 id) external view returns (Item memory);

    function keyEpoch(bytes32 key) external view returns (uint64);

    /// @notice The pending escape item for `target`, or zero.
    function pendingEscape(address target) external view returns (bytes32);

    function ESCAPE_DELAY() external view returns (uint256);

    function CONFIG_DELAY() external view returns (uint256);

    function GUARDIAN_DELAY() external view returns (uint256);

    function EXPIRY_WINDOW() external view returns (uint256);
}
