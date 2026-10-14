# ADR 0020: How the protected-state check reads and compares the Safe

- Status: Accepted
- Date: 2026-10-14

## Context

The post-check compares the protected fields against a pre-check snapshot (spec Post-check;
ADR 0001):

- singleton;
- guard and module guard;
- fallback handler;
- module list;
- owners;
- threshold.

The guard can't read another contract's storage directly, so it has to ask the Safe. After a
Bybit-style attack, though, **every** view call to the Safe executes the attacker's replacement
singleton, including `getStorageAt`, `getOwners`, `getThreshold` and `getModulesPaginated`. Such a
singleton can return the original values and pass a naive comparison.

## Decisions (owner, 2026-10-14)

1. **Trust order.** The singleton is read through the proxy's own `masterCopy()` shortcut, which
   the proxy bytecode answers from slot 0 without delegating:
   - `lib/safe-smart-account/contracts/proxies/SafeProxy.sol:42-45` (v1.5.0);
   - `git show v1.1.1:contracts/proxies/Proxy.sol` lines 34-38.

   The singleton is compared **first**. The other fields are read through the Safe's getters only
   after the singleton is confirmed unchanged, because only then does the code answering those
   getters belong to the singleton we trust.
2. **Encoding.**
   - Address fields are compared as `bytes32(uint256(uint160(a)))`.
   - The module list and owner list are compared as `keccak256(abi.encode(list))`.
   - The threshold is compared as `bytes32(threshold)`.
   - A difference reverts with `ProtectedStateChanged(field, beforeValue, afterValue)`.
3. **R2 cancellation skips the comparison** (D2). The exact cancellation sets a transient marker.
   The post-hook skips the comparison but still clears the path. The marker exists only for that
   execution. The cancellation reaches only the Safe's `receive()`, so nothing protected can
   change, and skipping keeps R2 independent of any bug in the comparison code.
4. **Module list bound** (D3): `MAX_MODULES = 16`.
   - The list is read with `getModulesPaginated(SENTINEL_MODULES, MAX_MODULES)`, and `next` must
     equal `SENTINEL_MODULES` (`ModuleManager.sol:62, 203`). Otherwise the check reverts with
     `TooManyModules`.
   - **The state is prevented, not only detected:**
     - the install checker rejects Safes with more than 16 modules (Phase 9);
     - queueing an `enableModule` that would exceed 16 is rejected (Phase 5).
   - Escape (R1) and cancellation (R2) return **before** the module read, so even a Safe over the
     limit can't be permanently frozen.
5. **Test seams** (D1). `_checkOperation` and `_compareProtectedState` are `internal virtual`, so
   test-only subclasses can disable one half and prove the other half alone stops a Bybit-shaped
   payload.
   - **Nothing in `src/` may override them.** `script/check-seam-overrides.sh` fails if anything
     does, or if either seam isn't defined exactly once. It runs in CI.

## Consequences

- **Gas:** every guarded execution reads the owner and module lists twice, once in the pre-check
  and once in the post-check. The cost is measured in the Phase 2 report.
- **Corrupted lists fail closed.** A delegatecall that corrupts the owner or module linked list
  (rather than editing it validly) can make the getters revert during the post-check. The
  transaction then reverts with that error instead of `ProtectedStateChanged`. It is still
  blocked.
