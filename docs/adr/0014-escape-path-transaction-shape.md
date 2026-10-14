# ADR 0014: Exact shape of escape-path transactions and hook order

- Status: Accepted
- Date: 2026-10-14

## Context

R1 (threat model §2) says the escape path (guard removal or replacement) is handled first in both
hooks and returns before any policy code. That keeps a policy bug from freezing the Safe
permanently. But a fast return skips policy, so a loosely defined "escape-path transaction" would
let policy-violating calls ride along, for example inside a batch, or carrying a gas refund.

## Options

### A. Exact match on a single top-level call; everything else goes through the normal pipeline
- (+) The bypass surface is exactly the escape action, nothing more.
- (−) Escape actions can't be batched with anything.

### B. Recognize escape actions anywhere, including inside batches
- (−) The fast path would have to run the batch decoder, which R1 exists to avoid. It also lets
  other calls share the escape transaction.

## Decision

**Option A** (owner, 2026-10-14).

**An escape-path transaction is exactly one top-level call**:
- `operation == Call`;
- `value == 0`;
- refund fields zero;
- never inside a batch.

It must also be one of these two forms:

1. `to == GUARD`, with selector `queueEscape`, or (signed path only) `cancelEscape`.
2. `to == SAFE`, calling `setGuard(x)` or `setModuleGuard(x)`, where `x` matches a matured,
   unexpired escape item.

Everything else goes through the normal pipeline.

**Hook order** (pre-hooks):

1. caller check (`msg.sender == SAFE`);
2. reentrancy flag;
3. path flag (signed or module);
4. **refund fields zero** (ADR 0010; moved before R1 so escape and cancellation transactions
   cannot carry a refund drain);
5. R1 escape;
6. R2 cancellation;
7. slot snapshot;
8. policy pipeline.

**Module path:** escape-path calls and **all** config calls are **rejected**, not fast-returned
(ADR 0007, ADR 0008).

## Consequences

- R1 code depends only on:
  - the caller check;
  - transient flags;
  - refund-field equality;
  - a selector and argument match;
  - one storage read of the escape item.

  It must not import the batch decoder, the allowlist, the token bucket or the call classifier.
- The post-hook R1 fast return is driven by a transient marker set in the pre-hook, not
  re-derived. The post-hook does not receive calldata.
- Before returning, the fast return must still clear the transient state it set (reentrancy and
  path flags), so a later Safe execution in the same Ethereum transaction isn't blocked.

### Execution order for replacement (owner, 2026-10-14)

Safe caches the guard **per execution** (`Safe.sol:149`, `ModuleManager.sol:101`). Consider two
orders for executing a replacement escape item:

- **`setGuard(x)` first:** the following `setModuleGuard(x)` transaction is pre-checked by the
  **new** guard `x`, not by this guard. `x` has an empty queue, so its own self-call policy would
  block the call.
- **`setModuleGuard(x)` first, then `setGuard(x)`:** both transactions are pre-checked by this
  guard (it is still the transaction guard), which matches both against the escape item.

Rule, **enforced** by the guard:

- An escape item is executed as **`setModuleGuard(x)` first, then `setGuard(x)`**, as two separate
  transactions. This guard checks both.
- `setGuard(x)` is accepted **only if the module guard slot already equals `x`**. Otherwise it
  reverts.
- The item is marked used when `setGuard(x)` executes.

Aborting halfway: if signers cancel the item after `setModuleGuard(x)`, the module guard stays `x`.
Restoring this guard as module guard is then a new escape item (72h).

In between, the module path is already guarded by `x` and the transaction path still by this guard,
so there is no unguarded window during a replacement. For removal (`x == 0`), the module path is
unguarded between the two transactions, which is inherent to removal.
