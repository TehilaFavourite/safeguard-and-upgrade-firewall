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
