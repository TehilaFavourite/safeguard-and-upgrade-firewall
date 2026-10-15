# ADR 0005: Outflow accounting: enforce in the pre-check, record in the post-check

- Status: Accepted
- Date: 2026-10-09

## Context

A Safe transaction can fail without reverting. When `safeTxGas != 0` or `gasPrice != 0`, a failed
inner call does not revert `execTransaction` (`contracts/Safe.sol:184-193`). The nonce is consumed
and `checkAfterExecution(txHash, false)` is called (lines 203-204). The inner call's state changes
are rolled back, so no funds moved.

## Decision (owner)

Outflow is **recorded** in the post-check, and only when `success == true`. It is never recorded in
the pre-check.

## Consequences and unresolved design points

1. *(Refined by ADR 0012: the cap is now checked and debited in the post-check. The pre-check
   computes the amounts and may fail fast.)* **The cap is still enforced in the pre-check.** Recording in the post-check does not remove the
   need to block before execution. The pre-check computes the transaction's outflow and rejects it
   if `windowSpent + amount > cap`.
2. **The amount must be carried from pre-check to post-check.** `checkAfterExecution` receives only
   `(txHash, success)` (`Safe.sol:204`); the module path receives `(guardHash, success)` from the
   guard's own return value (`ModuleManager.sol:107, 120`). Options:
   - storage keyed by hash;
   - transient storage (EIP-1153, needs solc ≥ 0.8.24 and Cancun);
   - for the module path, encode it into the returned `moduleTxHash`.
3. **Nested execution (decision needed).** An inner call can call `safe.execTransaction` for the
   next nonce while the outer transaction is running. The outer transaction passed its pre-check
   but has not recorded its outflow, so the inner one sees a cap that isn't really there and both
   pass. Options:
   - **A. Block reentrancy** in both guard hooks (pattern in
     `contracts/examples/guards/ReentrancyTransactionGuard.sol`). Simple, but forbids legitimate
     nested Safe transactions.
   - **B. Reserve in the pre-check, release on failure.** The pre-check adds `amount` to a pending
     total that later checks see. The post-check turns it into recorded spend on success, or
     releases it on failure. Allows nesting, but has more state and more edge cases.
   **Decided (owner): A. Block reentrancy with a transient-storage flag (EIP-1153).** The flag is
   checked on entry and set in the pre-check, then cleared in the post-check. A revert discards
   transient writes, so a blocked transaction cannot leave the flag stuck. B was rejected as more
   complex for a rare case.

   Implications:
   - The same flag must be used in all four hooks (`checkTransaction`, `checkAfterExecution`,
     `checkModuleTransaction`, `checkAfterModuleExecution`). Otherwise a module transaction
     nested inside `execTransaction` escapes it.
   - If one guard instance serves several Safes, the flag must be keyed by Safe (`msg.sender`).
     Whether to have one guard per Safe or a shared instance is an open decision.
   - Requires solc ≥ 0.8.24 and EVM version `cancun` or later. Check support on any non-mainnet
     deployment target.
   - Legitimate nested Safe transactions are forbidden. This is accepted.
   **Transient representation (owner, 2026-10-14).** solc 0.8.28 supports `transient` only for
   value types. A `mapping … transient` or `address[] transient` fails with error 1834 (verified).
   Therefore:
   - Value-type transient state uses typed `transient` variables: the reentrancy flag, the path
     flag, slot snapshots and list hashes.
   - The per-token outflow totals use **one small assembly library**: a keccak-keyed transient map
     plus a bounded token list. At most **8 distinct tokens per transaction** (ETH counts as one);
     above that it reverts with `TooManyTokens`.
   - This is one of the **two places assembly is allowed** in `src/` (see below and
     `docs/engineering-principles.md`). It must have 100% line and branch coverage, and its slot
     derivation must be documented and collision-tested against the typed transient variables.

   **Second assembly exception: `MemoryReader` (owner, 2026-10-15; Phase 3).** The batch decoder
   reads fields from `bytes memory` (the hook's `data` can't be `calldata`: with 11 parameters that
   hits "stack too deep", verified).
   - **Options measured** with the real libraries (gas to read op, to, value, length and selector per
     entry of a batch of ERC-20 transfers):

     | Entries | Optimizer off (project setting): byte loop | `MemoryReader` | Optimizer on, 200 runs (reference): byte loop | `MemoryReader` |
     |---|---|---|---|---|
     | 1 | 43,476 | 4,510 | 25,946 | 2,461 |
     | 8 | 271,102 | 32,748 | 161,053 | 17,392 |
     | 32 | 1,051,534 | 129,564 | 624,277 | 68,584 |

     The full decoder (wrapper, padding and entry checks) at 32 entries costs 150,537 gas with the
     optimizer off.
   - **Rejected alternatives:**
     - a pure-Solidity byte loop, about 8-10× the cost;
     - reading the hook's `msg.data` by hand, which re-implements the ABI layout of the hook call;
     - `via_ir`, which changes the whole compiler pipeline.
   - **Constraints:**
     - read-only;
     - each read function does an overflow-safe bounds check, then exactly one `mload`, and there is
       no `mstore`;
     - the assembly is marked `memory-safe`;
     - fuzzed against a byte-by-byte reference, including fields ending at the last byte of the
       buffer (non-zero memory beyond it) and offsets near `type(uint256).max`;
     - 100% coverage.
4. **Time-based policies make blocked transactions come back to life.** A transaction blocked
   only by the rolling cap becomes valid again when the window rolls over, with no state change.
   See `docs/runbook.md`.
