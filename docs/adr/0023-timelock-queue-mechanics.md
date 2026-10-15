# ADR 0023: Timelock queue mechanics, the escape target, and the guardian

- Status: Accepted
- Date: 2026-10-15
- Builds on: ADR 0002 (timelock inside the guard), ADR 0008 (guardian), ADR 0011 (delays),
  ADR 0014 (escape shape), ADR 0018 (calls to the guard)

## Decisions (owner, 2026-10-15)

- **D1 Item identity.** `id = keccak256(abi.encode(kind, key, payload, queueNonce))`. The same action
  can be queued again as a new item once it has been cancelled, executed or expired.
- **D2 Execution of non-escape items** (for example a guardian change): **only by the Safe on the
  signed path**. Permissionless execution would change guard state without using a Safe nonce, and
  that could revive a blocked transaction (`docs/runbook.md`).
- **D3 Config and escape calls only as single top-level calls**, never inside a batch: one action
  per transaction, a clear bot signal, and a smaller R1 surface. Consequence for Phase 7: incident
  response needs multi-key reduction functions, for example `lowerCaps(tokens[], caps[])`, so it
  stays a single call (`docs/build-plan.md`).
- **D4 Expiry.** A permissionless `markExpired(id)`. It reverts unless the item has expired, and
  calling it again on an already-expired item is a no-op. Every `Queued` event also carries
  `expiresAt`.
- **D5 Guardian.** Required non-zero at construction, replace-only (it can never be removed), and
  `guardian != address(this)`. The same rules apply to a guardian change.
- **D6 P1 auto-cancel by key epochs.** Each item records its key's epoch at queue time. A
  power-reducing change advances the key's epoch, emitting `KeyEpochAdvanced(key, epoch)`, and
  every pending item for that key queued under an older epoch becomes unexecutable
  (`ItemSuperseded`). This is O(1), with no arrays of pending ids. The mechanism lands in Phase 4;
  the real reductions are wired in Phases 7 (caps) and 8 (withdrawal periods).
- **D7 When an escape item is consumed.** In the post-hook, only if `success == true`. Otherwise a
  failed `safeTxGas > 0` execution would burn the item while leaving the guard unchanged.
- **One pending escape item per target.** `setModuleGuard(x)` and `setGuard(x)` carry no item id, so
  the guard matches them by target. Queuing a second escape for the same target while one is
  pending reverts.

## I4.20 (critical): the escape target must be bound to this Safe

A replacement guard bound to a different Safe would make every transaction revert with `NotSafe`,
escape and cancellation included. That is a **permanent freeze**. Therefore, for `x != 0`, at
`queueEscape` **and** at execution (both `setModuleGuard(x)` and `setGuard(x)`):

- `x` must have the bound `extcodehash` (ADR 0014);
- a STATICCALL to `x.SAFE()` must return this Safe;
- `x.supportsInterface` must return true for `ITransactionGuard` and `IModuleGuard`.

Otherwise the call reverts with `EscapeTargetNotBound(x, reportedSafe)`. Failing calls, reverts or
malformed return data from `x` are reported with `reportedSafe = address(0)`.

- **Removal (`x == 0`) is always allowed.** It's the escape of last resort if a target misbehaves,
  for example by burning gas in `SAFE()`.
- **v1 replacements must be this guard type, or removal.**
- **Not rejected: a replacement with a wrong `expectedSingleton`.** Once installed, its ordinary
  transactions revert with `UnexpectedSingleton`, but its R1 and R2 still work, because they run
  before its step-8 check. So it fails closed and is recoverable through its own escape. A test
  documents this.
- **The calls to `x` are STATICCALLs.** `script/check-guard-opcodes.sh` must still report zero
  CALL, DELEGATECALL or CALLCODE.

## Consequences for R1 (amends ADR 0014's dependency list)

R1 now also depends on:
- one read of the module guard slot (the `setGuard` order check);
- `extcodehash(x)`;
- three STATICCALLs to `x` (I4.20).

It still doesn't touch the batch decoder, the allowlist, the token bucket or the call classifier.
