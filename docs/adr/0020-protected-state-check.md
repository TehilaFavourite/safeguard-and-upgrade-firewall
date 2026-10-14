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
   - The singleton is compared as `bytes32(uint256(uint160(a)))`, read from `masterCopy()`.
   - Slot-backed fields (guard, module guard, fallback handler) are compared as the raw 32-byte
     slot word. For a clean address that equals the same encoding, and it is stricter: any change
     to the slot is caught.
   - The module list and owner list are compared as `keccak256(abi.encode(list))`.
   - The threshold is compared as `bytes32(threshold)`.
   - A difference reverts with `ProtectedStateChanged(field, beforeValue, afterValue)`.
3. **R2 cancellation skips the comparison** (D2). The exact cancellation sets a transient marker.
   The post-hook skips the comparison but still clears the path. The marker exists only for that
   execution. The cancellation reaches only the Safe's `receive()`, so nothing protected can
   change, and skipping keeps R2 independent of any bug in the comparison code.
4. **Module list bound** (D3): `MAX_MODULES = 16`.
   - The list is read with `getModulesPaginated(SENTINEL_MODULES, MAX_MODULES + 1)`, which bounds
     the Safe's loop at 17 iterations (`ModuleManager.sol:212`).
   - 17 entries returned: over the limit, **or a cycle**. This reverts with `TooManyModules(16)`.
     The read is bounded, so a cycle cannot run out of gas.
   - Fewer entries but `next != SENTINEL_MODULES`: the list ended at `address(0)` without reaching
     the sentinel (`ModuleManager.sol:226-227`). This reverts with
     `ModuleListNotTerminated(next)`.
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

6. **Expected singleton** (I2.23; owner, 2026-10-14).
   - The guard records an expected singleton: a constructor argument, checked during install
     (Phase 9), and updated only when an ADR 0015 migration item executes (Phase 8).
   - Every pre-hook requires `masterCopy() == expectedSingleton`, or reverts with
     `UnexpectedSingleton(actual, expected)`.
   - **Placement:** after step 7 and before the snapshot. Escape (R1) and cancellation (R2) return
     earlier, so they still work on an already-compromised Safe.
   - **Reason:** the comparison only catches changes made *during* a transaction. This check
     catches a Safe that was *already* wrong.
   - The post-check compares `masterCopy()` against the expected singleton. No separate snapshot
     is needed.

## Consequences

- **Gas:** every guarded execution reads the owner and module lists twice, once in the pre-check
  and once in the post-check. The cost is measured in the Phase 2 report.
- **Corrupted lists fail closed, with pinned errors** (owner, 2026-10-14):

  | Corruption | Result |
  |---|---|
  | Module list cycle | `TooManyModules(16)`, from the bounded read |
  | Module list not terminated by the sentinel | `ModuleListNotTerminated(next)` |
  | Owner list not terminated | The Safe's own `getOwners()` reverts. It has no bound and writes past its array (`OwnerManager.sol:135-144`). The revert data **differs by variant, deterministically** |

  The owner-list revert data, by variant:
  - **Local build (solc 0.8.28):** `Panic(0x32)`, array index out of bounds.
  - **Mainnet singleton (solc 0.7.6):** the `invalid` opcode, with **empty** revert data. It also
    consumes the gas forwarded to that call.

  Each case has a paired control test: the same transaction writing the current value succeeds.
