// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {IModuleGuard} from "safe-smart-account/contracts/base/ModuleManager.sol";
import {IERC165} from "safe-smart-account/contracts/interfaces/IERC165.sol";
import {IGuardManager} from "safe-smart-account/contracts/interfaces/IGuardManager.sol";
import {IModuleManager} from "safe-smart-account/contracts/interfaces/IModuleManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "./interfaces/ISafeFirewallGuard.sol";
import {SafeSlots} from "./libraries/SafeSlots.sol";
import {MultiSendDecoder} from "./libraries/MultiSendDecoder.sol";
import {MemoryReader} from "./libraries/MemoryReader.sol";

/// @title SafeFirewallGuard
/// @notice Transaction guard and module guard bound to a single Safe v1.5.0 (ADR 0001, ADR 0007).
/// @dev Phase 4 scope: the hook prefix, the refund ban, R1 escape, R2 cancellation, calls to the
///      guard, the expected-singleton check, the delegatecall policy, strict batch decoding, the
///      protected-state snapshot/compare, and the timelock queue with escape and guardian items.
///      ⚠️ Not deployable before Phase 10: the allowlist and caps are not yet in place
///      (docs/build-plan.md).
///      Not upgradeable. Replacement happens only through the escape path (ADR 0014).
contract SafeFirewallGuard is ISafeFirewallGuard {
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override SAFE;
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override MULTISEND_CALL_ONLY;
    /// @inheritdoc ISafeFirewallGuard
    address public immutable override PERMIT2;

    /// @inheritdoc ISafeFirewallGuard
    uint256 public constant override ESCAPE_DELAY = 72 hours; // ADR 0011
    /// @inheritdoc ISafeFirewallGuard
    uint256 public constant override CONFIG_DELAY = 48 hours; // ADR 0011
    /// @inheritdoc ISafeFirewallGuard
    uint256 public constant override GUARDIAN_DELAY = 48 hours; // ADR 0011
    /// @inheritdoc ISafeFirewallGuard
    uint256 public constant override EXPIRY_WINDOW = 14 days; // ADR 0011

    /// @dev ADR 0019 rejects using a module transaction hash.
    bytes32 private constant NO_MODULE_TX_HASH = bytes32(0);
    /// @dev The key of guardian-change items (ADR 0023, D6).
    bytes32 private constant GUARDIAN_KEY = keccak256("safe-firewall.key.guardian");
    /// @dev The key of escape items. Not reduced by any power-reducing change.
    bytes32 private constant ESCAPE_KEY = keccak256("safe-firewall.key.escape");
    /// @dev `setGuard(address)` / `setModuleGuard(address)` calldata: selector + one ABI word.
    uint256 private constant ONE_ARG_CALLDATA = 36;
    /// @dev `queueEscape(address,bytes32)` calldata: selector + two ABI words.
    uint256 private constant TWO_ARG_CALLDATA = 68;
    uint256 private constant SELECTOR_SIZE = 4;
    uint256 private constant ADDRESS_BITS = 160;
    uint256 private constant ABI_WORD = 32;

    /// @dev Which fast path the pre-check took; the post-hook skips the comparison for both.
    enum FastPath {
        NONE,
        CANCELLATION, // R2 (threat model; ADR 0020 D2)
        ESCAPE // R1 (ADR 0014)
    }

    struct EscapeTarget {
        address target;
        bytes32 codehash;
    }

    /// @dev The singleton the Safe must run on (I2.23). Storage: a timelocked migration item
    ///      (ADR 0015, Phase 8) is the only thing that will update it.
    address private _expectedSingleton;
    /// @dev The cancel-only guardian (ADR 0008, ADR 0023 D5).
    address private _guardian;
    /// @dev Makes item ids unique, so the same action can be queued again (ADR 0023, D1).
    uint256 private _queueNonce;

    mapping(bytes32 id => Item) private _items;
    mapping(bytes32 key => uint64) private _keyEpochs;
    mapping(bytes32 id => EscapeTarget) private _escapes;
    mapping(address target => bytes32 id) private _pendingEscapes;
    mapping(bytes32 id => address) private _guardianChanges;

    /// @dev The execution currently being guarded. `NONE` means no execution is active, so this
    ///      one variable is both the reentrancy flag and the path record (ADR 0005, ADR 0007).
    ExecutionPath private transient _path;
    /// @dev Set by R1 or R2; makes the post-hook skip the comparison. Lives only for one execution.
    FastPath private transient _fastPath;
    /// @dev The escape item a matched `setGuard(x)` will consume if the execution succeeds (D7).
    bytes32 private transient _escapeToConsume;

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
        _requireValidGuardian(config.guardian);
        SAFE = config.safe;
        MULTISEND_CALL_ONLY = config.multiSendCallOnly;
        PERMIT2 = config.permit2;
        _expectedSingleton = config.singleton;
        _guardian = config.guardian;
    }

    // ------------------------------------------------------------------------- transaction guard

    /// @notice Pre-check for `Safe.execTransaction`, called after signature verification
    ///         (lib/safe-smart-account/contracts/Safe.sol:147-152).
    /// @dev Order follows ADR 0014 (amended by ADR 0020):
    ///      (1) caller check → (2) reentrancy → (3) path → (4) refund fields → (5) R1 escape →
    ///      (6) R2 cancellation → (7) reject other calls to GUARD → (8) expected singleton →
    ///      (9) protected-state snapshot → (10) policy pipeline.
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
        if (_isEscape(to, value, data, operation)) {
            _fastPath = FastPath.ESCAPE; // step 5, R1 (ADR 0014)
            return;
        }
        if (_isCancellation(to, value, data, operation)) {
            _fastPath = FastPath.CANCELLATION; // step 6, R2 (ADR 0020 D2)
            return;
        }
        _rejectCallToGuard(to, value, data, operation, ExecutionPath.SIGNED); // step 7 (ADR 0018)
        _requireExpectedSingleton(); // step 8 (ADR 0020, I2.23)
        _snapshotProtectedState(); // step 9 (ADR 0020)
        _checkOperation(to, operation, ExecutionPath.SIGNED); // step 10, policy pipeline (ADR 0003)
        _checkBatch(to, value, data, operation); // step 10, each inner call of a batch (ADR 0003)
    }

    /// @notice Post-check for `Safe.execTransaction`, called on the guard address cached before
    ///         execution (Safe.sol:149, 203-204; ADR 0001).
    /// @dev Pairing first (ADR 0018). A fast path skips the comparison; an R1 `setGuard` consumes its
    ///      item only if the execution succeeded (ADR 0023, D7). Otherwise the protected-state
    ///      comparison runs, whether or not the inner call succeeded (I2.14).
    function checkAfterExecution(bytes32, bool success) external override {
        _exit(ExecutionPath.SIGNED);
        FastPath fastPath = _fastPath;
        if (fastPath != FastPath.NONE) {
            _fastPath = FastPath.NONE; // the marker lives only for this execution
            bytes32 consume = _escapeToConsume;
            if (consume != bytes32(0)) {
                _escapeToConsume = bytes32(0);
                if (success) _consumeEscape(consume);
            }
            return;
        }
        _compareProtectedState();
        _clearSnapshot();
    }

    // ------------------------------------------------------------------------------ module guard

    /// @notice Pre-check for `execTransactionFromModule*`, called before execution
    ///         (lib/safe-smart-account/contracts/base/ModuleManager.sol:106-108).
    /// @dev Module-path order: (1-3) prefix → (7) reject every call to GUARD → (8) expected singleton
    ///      → (9) snapshot → (10) pipeline. There are no fast paths on the module path: escape and
    ///      config calls are rejected at step 7, and a matched `setGuard` gets the post-check
    ///      (ADR 0014). The returned hash is unused (ADR 0019).
    /// @return `NO_MODULE_TX_HASH`.
    function checkModuleTransaction(address to, uint256 value, bytes memory data, Enum.Operation operation, address)
        external
        override
        returns (bytes32)
    {
        _enter(ExecutionPath.MODULE); // steps 1-3
        _rejectCallToGuard(to, value, data, operation, ExecutionPath.MODULE); // step 7 (ADR 0018)
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

    // ------------------------------------------------------------------------------- escape (R1)

    /// @inheritdoc ISafeFirewallGuard
    /// @dev Reached through R1 (ADR 0014). For `target != 0`, the target must have `codehash` and be
    ///      a guard bound to this Safe (I4.20, ADR 0023). One pending escape item per target.
    function queueEscape(address target, bytes32 codehash) external override returns (bytes32 id) {
        _requireSignedPath();
        if (target != address(0)) {
            _requireEscapeTarget(target, codehash);
        } else if (codehash != bytes32(0)) {
            revert EscapeCodehashMismatch(target, codehash, bytes32(0));
        }
        bytes32 pending = _pendingEscapes[target];
        if (pending != bytes32(0) && _isLive(pending)) revert EscapeAlreadyPending(target, pending);

        id = _queue(ItemKind.ESCAPE, ESCAPE_KEY, abi.encode(target, codehash));
        _escapes[id] = EscapeTarget({target: target, codehash: codehash});
        _pendingEscapes[target] = id;
    }

    /// @inheritdoc ISafeFirewallGuard
    /// @dev Reached through R1 (ADR 0014), so signers can cancel even when policy is broken.
    function cancelEscape(bytes32 id) external override {
        _requireSignedPath();
        Item storage item = _requireQueued(id);
        if (item.kind != ItemKind.ESCAPE) revert WrongItemKind(id, ItemKind.ESCAPE, item.kind);
        _clearPendingEscape(id);
        _cancel(id, item, SAFE);
    }

    // ---------------------------------------------------------------------------- guardian items

    /// @inheritdoc ISafeFirewallGuard
    function queueGuardianChange(address newGuardian) external override returns (bytes32 id) {
        _requireSignedPath();
        _requireValidGuardian(newGuardian);
        id = _queue(ItemKind.GUARDIAN_CHANGE, GUARDIAN_KEY, abi.encode(newGuardian));
        _guardianChanges[id] = newGuardian;
    }

    /// @inheritdoc ISafeFirewallGuard
    function executeGuardianChange(bytes32 id) external override {
        _requireSignedPath();
        Item storage item = _requireQueued(id);
        if (item.kind != ItemKind.GUARDIAN_CHANGE) revert WrongItemKind(id, ItemKind.GUARDIAN_CHANGE, item.kind);
        _requireExecutable(id);

        item.status = ItemStatus.EXECUTED;
        address previous = _guardian;
        address current = _guardianChanges[id];
        _guardian = current;
        emit Executed(id, ItemKind.GUARDIAN_CHANGE);
        emit GuardianChanged(previous, current);
    }

    // ------------------------------------------------------------------------------ cancel / expiry

    /// @inheritdoc ISafeFirewallGuard
    function cancel(bytes32 id) external override {
        _requireSignedPath();
        Item storage item = _requireQueued(id);
        if (item.kind == ItemKind.ESCAPE) revert EscapeRequiresCancelEscape(id);
        _cancel(id, item, SAFE);
    }

    /// @inheritdoc ISafeFirewallGuard
    /// @dev Cancelling only reduces power (P1). The guardian can't cancel escape items or guardian
    ///      changes, so a rogue guardian can't keep the Safe frozen or block its own removal (ADR 0008).
    function guardianCancel(bytes32 id) external override {
        if (msg.sender != _guardian) revert NotGuardian(msg.sender);
        Item storage item = _requireQueued(id);
        if (item.kind == ItemKind.ESCAPE || item.kind == ItemKind.GUARDIAN_CHANGE) {
            revert GuardianCannotCancel(id, item.kind);
        }
        _cancel(id, item, msg.sender);
    }

    /// @inheritdoc ISafeFirewallGuard
    /// @dev Anyone. Only reduces power. A no-op on an already-expired item (ADR 0023, D4).
    function markExpired(bytes32 id) external override {
        Item storage item = _items[id];
        if (item.status == ItemStatus.EXPIRED) return;
        if (item.status != ItemStatus.QUEUED) revert ItemNotQueued(id, item.status);
        if (block.timestamp < item.expiresAt) revert NotExpiredYet(id, item.expiresAt);
        item.status = ItemStatus.EXPIRED;
        if (item.kind == ItemKind.ESCAPE) _clearPendingEscape(id);
        emit Expired(id, item.kind);
    }

    // ------------------------------------------------------------------------------------- views

    /// @inheritdoc ISafeFirewallGuard
    function expectedSingleton() external view override returns (address) {
        return _expectedSingleton;
    }

    /// @inheritdoc ISafeFirewallGuard
    function guardian() external view override returns (address) {
        return _guardian;
    }

    /// @inheritdoc ISafeFirewallGuard
    function getItem(bytes32 id) external view override returns (Item memory) {
        return _items[id];
    }

    /// @inheritdoc ISafeFirewallGuard
    function keyEpoch(bytes32 key) external view override returns (uint64) {
        return _keyEpochs[key];
    }

    /// @inheritdoc ISafeFirewallGuard
    function pendingEscape(address target) external view override returns (bytes32) {
        return _pendingEscapes[target];
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

    // ------------------------------------------------------------------------- queue (internal)

    /// @dev Queues an item: ETA = now + class delay; expires EXPIRY_WINDOW after the ETA; records the
    ///      key's current epoch (ADR 0023, D1 and D6).
    function _queue(ItemKind kind, bytes32 key, bytes memory payload) internal returns (bytes32 id) {
        id = keccak256(abi.encode(kind, key, payload, _queueNonce++));
        uint64 eta = uint64(block.timestamp + _delay(kind));
        uint64 expiresAt = uint64(eta + EXPIRY_WINDOW);
        _items[id] = Item({
            kind: kind,
            status: ItemStatus.QUEUED,
            key: key,
            eta: eta,
            expiresAt: expiresAt,
            keyEpoch: _keyEpochs[key],
            payloadHash: keccak256(payload)
        });
        emit Queued(id, kind, key, eta, expiresAt, payload);
    }

    /// @dev Advances `key`'s epoch, superseding every pending item queued for it before now (ADR 0023,
    ///      D6). Called by power-reducing changes from Phases 7 and 8.
    function _advanceKeyEpoch(bytes32 key) internal {
        uint64 epoch = ++_keyEpochs[key];
        emit KeyEpochAdvanced(key, epoch);
    }

    /// @dev Reverts unless the item is queued, matured, not expired and on its key's current epoch.
    function _requireExecutable(bytes32 id) internal view {
        Item storage item = _requireQueued(id);
        if (block.timestamp < item.eta) revert NotMatured(id, item.eta);
        if (block.timestamp >= item.expiresAt) revert ItemExpired(id, item.expiresAt);
        uint64 current = _keyEpochs[item.key];
        if (item.keyEpoch != current) revert ItemSuperseded(id, item.keyEpoch, current);
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

    /// @dev Config functions: callable only by the Safe, inside a signed-path execution (ADR 0007,
    ///      ADR 0023). Step 7 already rejects module-path and batch calls to the guard; this is the
    ///      check at the function itself.
    function _requireSignedPath() private view {
        if (msg.sender != SAFE) revert NotSafe(msg.sender);
        ExecutionPath active = _path;
        if (active != ExecutionPath.SIGNED) revert NotSignedPath(active);
    }

    /// @dev Step 4 (ADR 0010): all three refund fields must be zero. `handlePayment` runs only when
    ///      gasPrice > 0 (Safe.sol:196); gasToken and refundReceiver are banned as well, so the rule
    ///      reads simply.
    function _requireNoRefund(uint256 gasPrice, address gasToken, address refundReceiver) private pure {
        if (gasPrice != 0 || gasToken != address(0) || refundReceiver != address(0)) {
            revert RefundNotAllowed(gasPrice, gasToken, refundReceiver);
        }
    }

    /// @dev Step 5, R1 recognition (ADR 0014; I4.6). An escape-path transaction is exactly one
    ///      top-level `Call` with value 0 (refund fields were checked at step 4), and one of:
    ///        a. GUARD.queueEscape(target, codehash) or GUARD.cancelEscape(id), exact calldata length.
    ///           The function itself does the remaining checks.
    ///        b. SAFE.setModuleGuard(x) or SAFE.setGuard(x), clean ABI argument, where x has a pending
    ///           escape item. That item must be executable (matured, unexpired, current epoch) and x
    ///           must still pass the I4.20 target checks; `setGuard(x)` additionally requires the
    ///           module guard slot to already equal x (enforced order). Each failure reverts with its
    ///           own error. A matched `setGuard(x)` marks its item to be consumed in the post-hook,
    ///           only if the execution succeeds (D7).
    ///      Anything else, including a `setGuard`/`setModuleGuard` with no pending item, returns false
    ///      and takes the normal pipeline, where the post-check catches any guard-slot change. R1
    ///      never runs the batch decoder, the expected-singleton check, the snapshot or the policy
    ///      seams.
    function _isEscape(address to, uint256 value, bytes memory data, Enum.Operation operation) private returns (bool) {
        if (operation != Enum.Operation.Call || value != 0 || data.length < SELECTOR_SIZE) return false;
        bytes4 selector = MemoryReader.readBytes4(data, 0);

        if (to == address(this)) {
            return (selector == this.queueEscape.selector && data.length == TWO_ARG_CALLDATA)
                || (selector == this.cancelEscape.selector && data.length == ONE_ARG_CALLDATA);
        }
        if (to != SAFE || data.length != ONE_ARG_CALLDATA) return false;
        bool isSetGuard = selector == IGuardManager.setGuard.selector;
        if (!isSetGuard && selector != IModuleManager.setModuleGuard.selector) return false;

        uint256 word = MemoryReader.readUint256(data, SELECTOR_SIZE);
        if (word >> ADDRESS_BITS != 0) return false; // dirty address encoding: not an escape shape
        address target = address(uint160(word));
        bytes32 id = _pendingEscapes[target];
        if (id == bytes32(0)) return false;

        _requireExecutable(id);
        if (target != address(0)) _requireEscapeTarget(target, _escapes[id].codehash);
        if (isSetGuard) {
            address moduleGuard = address(uint160(uint256(SafeSlots.word(SAFE, SafeSlots.MODULE_GUARD_SLOT))));
            if (moduleGuard != target) revert EscapeOrderViolation(target, moduleGuard);
            _escapeToConsume = id;
        }
        return true;
    }

    /// @dev I4.20 (ADR 0023): the escape target must have the bound code and be a guard bound to this
    ///      Safe, or installing it would freeze the Safe permanently (every hook would revert NotSafe).
    ///      All three reads are STATICCALLs. Any failure (the call fails, return data shorter than 32
    ///      bytes, or a value that isn't a clean address or bool) reports `EscapeTargetNotBound`. A hostile
    ///      target can waste gas, for example with oversized return data. That is accepted: only signers
    ///      choose the target, and a failure fails closed (the item can't be queued or executed).
    function _requireEscapeTarget(address target, bytes32 codehash) private view {
        bytes32 actual = target.codehash;
        if (actual != codehash) revert EscapeCodehashMismatch(target, codehash, actual);

        (bool ok, uint256 reported) = _staticWord(target, abi.encodeCall(ISafeFirewallGuard.SAFE, ()));
        address reportedSafe = ok && reported >> ADDRESS_BITS == 0 ? address(uint160(reported)) : address(0);
        if (reportedSafe != SAFE) revert EscapeTargetNotBound(target, reportedSafe);
        if (
            !_supports(target, type(ITransactionGuard).interfaceId)
                || !_supports(target, type(IModuleGuard).interfaceId)
        ) {
            revert EscapeTargetNotBound(target, reportedSafe);
        }
    }

    function _supports(address target, bytes4 interfaceId) private view returns (bool) {
        (bool ok, uint256 result) = _staticWord(target, abi.encodeCall(IERC165.supportsInterface, (interfaceId)));
        return ok && result == 1;
    }

    /// @dev STATICCALL: success, then at least one ABI word of return data, then decode.
    function _staticWord(address target, bytes memory callData) private view returns (bool ok, uint256 word) {
        bytes memory ret;
        (ok, ret) = target.staticcall(callData);
        if (!ok || ret.length < ABI_WORD) return (false, 0);
        word = abi.decode(ret, (uint256));
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

    /// @dev Step 7 (ADR 0018, I4.19): a call to the guard is rejected unless it is a single top-level
    ///      signed-path `Call` with value 0 to one of the closed list of Safe-callable guard functions.
    ///      On the module path every call to the guard is rejected (ADR 0014). Calldata shorter than 4
    ///      bytes reports a zero-padded selector.
    function _rejectCallToGuard(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        ExecutionPath path
    ) private view {
        if (to != address(this)) return;
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes4 selector = bytes4(data); // intended: first 4 bytes = selector
        if (path == ExecutionPath.SIGNED && operation == Enum.Operation.Call && value == 0 && _isSafeCallable(selector))
        {
            return;
        }
        revert GuardCallRejected(selector);
    }

    /// @dev The closed list of guard functions the Safe may call (I4.19). Hooks are never on it.
    function _isSafeCallable(bytes4 selector) private pure returns (bool) {
        return selector == ISafeFirewallGuard.queueEscape.selector
            || selector == ISafeFirewallGuard.cancelEscape.selector
            || selector == ISafeFirewallGuard.queueGuardianChange.selector
            || selector == ISafeFirewallGuard.executeGuardianChange.selector
            || selector == ISafeFirewallGuard.cancel.selector;
    }

    /// @dev Step 8 (ADR 0020, I2.23): catches a Safe that was already compromised before this
    ///      transaction. The comparison only catches changes made during it.
    function _requireExpectedSingleton() private view {
        address actual = SafeSlots.masterCopy(SAFE);
        address expected = _expectedSingleton;
        if (actual != expected) revert UnexpectedSingleton(actual, expected);
    }

    /// @dev Step 10 for batches (ADR 0003). Applies only to a DelegateCall to MULTISEND_CALL_ONLY, the
    ///      only delegatecall `_checkOperation` lets through on the signed path:
    ///      - the outer value must be zero (D2);
    ///      - the batch is decoded strictly;
    ///      - each inner call goes through the same per-call policy as a top-level Call. Inner calls to
    ///        the guard are always rejected, so config and escape calls are top-level only (ADR 0023 D3).
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

    function _consumeEscape(bytes32 id) private {
        _items[id].status = ItemStatus.EXECUTED;
        _clearPendingEscape(id);
        emit Executed(id, ItemKind.ESCAPE);
    }

    function _cancel(bytes32 id, Item storage item, address by) private {
        item.status = ItemStatus.CANCELLED;
        emit Cancelled(id, item.kind, by);
    }

    function _clearPendingEscape(bytes32 id) private {
        address target = _escapes[id].target;
        if (_pendingEscapes[target] == id) delete _pendingEscapes[target];
    }

    function _requireQueued(bytes32 id) private view returns (Item storage item) {
        item = _items[id];
        if (item.status != ItemStatus.QUEUED) revert ItemNotQueued(id, item.status);
    }

    /// @dev Queued and not yet expired: still able to execute (one pending escape per target).
    function _isLive(bytes32 id) private view returns (bool) {
        Item storage item = _items[id];
        return item.status == ItemStatus.QUEUED && block.timestamp < item.expiresAt;
    }

    function _delay(ItemKind kind) private pure returns (uint256) {
        if (kind == ItemKind.ESCAPE) return ESCAPE_DELAY;
        if (kind == ItemKind.GUARDIAN_CHANGE) return GUARDIAN_DELAY;
        return CONFIG_DELAY;
    }

    /// @dev ADR 0023, D5: the guardian is non-zero and never the guard itself.
    function _requireValidGuardian(address candidate) private view {
        if (candidate == address(0) || candidate == address(this)) revert InvalidGuardian(candidate);
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
