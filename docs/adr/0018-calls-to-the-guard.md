# ADR 0018: Calls from the Safe to the guard itself

- Status: Accepted
- Date: 2026-10-14

## Context

All four hooks require `msg.sender == SAFE` (ADR 0007). Any call that **originates from the Safe**
satisfies that, including a call the signers (or a module) direct at the guard. Examples: a
top-level transaction, a batch inner call, or a module transaction with `to == GUARD` and a hook
selector.

Such a call reaches the hook while a real execution is active. For example, calling
`checkAfterExecution` mid-execution would compare slots early and clear the transient snapshot and
flags before the real post-check runs. It could also debit or clear outflow state.

## Options

### A. Reject in the pipeline: `to == GUARD` is only allowed for config and escape selectors
### B. Make every hook detect being called "out of turn"
- (−) Each hook needs its own state machine. Easy to get subtly wrong.

## Decision

**Option A** (owner, 2026-10-14).

- Any call with `to == GUARD` is rejected unless its selector is a guard config or escape function.
  That covers top-level calls, batch inner calls and module calls.
- Hook selectors are always rejected.
- `GUARD` can never be an allowlisted target.

**This pipeline rule is the real control.** Defence in depth: a post-hook reverts with
`NoActiveExecution` unless a pre-hook is active on the same path (Phase 1 invariant I1.9). That
check alone is **not** sufficient: a hook called mid-execution does see an active pre-hook.

## Consequences

- The list of permitted guard selectors is explicit and closed. Adding a config function means
  adding it to that list, and a test asserts that the list matches the guard's config ABI.
- In Phase 1 no config selectors exist yet, so every top-level call to `GUARD` reverts
  (invariant I1.12). Batch inner calls are covered in Phase 3, module calls in Phase 5.
- The escape path (ADR 0014) uses guard selectors (`queueEscape`, `cancelEscape`). These are on
  the permitted list and are matched before the pipeline.
