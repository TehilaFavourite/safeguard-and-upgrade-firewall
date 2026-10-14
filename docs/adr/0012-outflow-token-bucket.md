# ADR 0012: Outflow window as a per-token token bucket

- Status: Accepted
- Date: 2026-10-09
- Refines: ADR 0005 (moves cap enforcement from the pre-check to the post-check)

## Context

ADR 0004 sets per-token caps over a rolling window, but doesn't define the window. The choice
affects storage, gas, the worst-case loss, and when a transaction blocked by the cap becomes valid
again.

## Options

### A. Per-token token bucket
Capacity = cap, refilling linearly at cap per 24h.
- (+) O(1) storage per token (level and last update).
- (+) No reset moment to time an attack around.

### B. Fixed 24h buckets (reset at boundaries)
- (−) Same 2× cap bound as A, plus timing games at the reset (spend the cap just before the reset
  and again just after).

### C. True sliding window (log of every outflow)
- (−) Unbounded storage and gas.

## Decision

**Option A.** Checked and debited in the post-check, consistent with ADR 0005's decision to record
only when `success == true`.

**Bounds:**
- at most **cap per transaction** (a batch counts as one transaction);
- at most **2× cap in any 24h period** (a full bucket plus 24h of refill).

## Consequences

- **Enforcement moves to the post-check.** ADR 0005 said the cap is enforced in the pre-check;
  this ADR moves it to the post-check. A revert in the post-check undoes the whole transaction,
  so enforcement is equivalent. Reentrancy is blocked (ADR 0005), so no nested transaction sees a
  stale level.
- **Passing the amount.** The pre-check still computes the transaction's per-token totals and
  passes them to the post-check through transient storage. `checkAfterExecution` only receives
  `(txHash, success)`.
- **Optional fail-fast.** The pre-check may also reject a transaction whose total exceeds the
  current level, to fail before execution and save gas. The post-check stays authoritative.
- **Deny by default.** Unconfigured tokens have capacity 0 (P2).
- **Blocked transactions.** A transaction blocked by the cap becomes valid again as the bucket
  refills, without any state change. The runbook's immediate cancellation applies.

## Cap changes (owner, 2026-10-10)

- **Settle first.** Before any cap change, settle the bucket to the current timestamp using the
  **old** rate. The new rate never applies retroactively to time that has already passed.
- **Raising** keeps the current level. It refills at the new rate, with no instant top-up.
  Timelocked (48h config).
- **Lowering** clamps the level to the new cap. Immediate through the signed path (P1).
- **Lowering also cancels pending raises.** A power-reducing change to a key (here, a token's cap)
  cancels every pending power-adding change to that same key. Otherwise an incident-time lowering
  would be undone when an already-queued raise matures. Cancelling only reduces power (P1).
  Immediate lowering is signed-path only, so it can't be used for griefing.
