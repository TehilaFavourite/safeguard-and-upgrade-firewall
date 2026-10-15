# Operations Runbook

## When the guard blocks a transaction

**Why it matters.** A guard revert rolls back the whole `execTransaction`, including `nonce++`
(`contracts/Safe.sol:145`), so the blocked transaction's nonce is still unused and its signatures
remain valid. Nonces are strictly sequential, so the next Safe transaction executed at that nonce
invalidates it.

**The risk is the window before that happens.** In that window the blocked transaction can become
executable without any Safe transaction:

- a time-based policy changes on its own (e.g. the rolling outflow window rolls over);
- guard state changes through a path that doesn't use a Safe nonce: a module transaction, or a
  timelocked config change whose `execute` is callable by anyone (ADR 0002);
- the guard or its storage slot is changed through the module path.

**Procedure:**

1. Treat the blocked transaction as an incident. Someone tricked the signers once.
2. **Immediately** execute a cancellation at the same nonce: a zero-value call from the Safe to
   itself with empty data. This uses up the nonce and permanently invalidates the blocked
   transaction's signatures.
3. Confirm on-chain that the Safe's `nonce` is now past the blocked transaction's nonce.
4. Review how the transaction was presented to signers (UI, calldata, simulation) before signing
   anything else.

## Executing an escape (replacing or removing the guard)

An escape is two Safe transactions with a fixed order (ADR 0014): `setModuleGuard(x)` first, then
`setGuard(x)`. The guard rejects `setGuard(x)` unless the module guard is already `x`.

1. After the 72h delay, and before `expiresAt` (14 days later), sign and execute
   `setModuleGuard(x)`.
2. **Immediately** sign and execute `setGuard(x)`. Prepare and collect signatures for both before
   executing the first, so they run back to back (consecutive nonces).
3. Confirm on-chain that both guard slots now hold `x` and that the escape item's status is
   `EXECUTED`.

**Never cancel an escape item between its two steps.** Don't let it expire between them either.
Either leaves a **mixed state**: module guard `x`, transaction guard = this guard. It fails closed,
but it can't be undone quickly.

**Recovering from a mixed state:** queue an escape back to this guard, which is a 72h delay
(`queueEscape(thisGuard, thisGuard.codehash)`, then `setModuleGuard(thisGuard)`, then
`setGuard(thisGuard)`). The last step changes nothing, but it consumes the item, so no escape item
is left pending. Alternatively,
queue a fresh escape to `x` and finish both steps. Until then, module transactions are checked by
`x`, and signed transactions by this guard.
