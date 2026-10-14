# ADR 0010: Ban gas refunds on every transaction

- Status: Accepted
- Date: 2026-10-09

## Context

`handlePayment` (`contracts/Safe.sol:217-235`) pays `(gasUsed + baseGas) * gasPrice` to
`refundReceiver` (or `tx.origin`) in `gasToken`. It is called only when `gasPrice > 0`
(lines 196-198).

For ERC-20 gas tokens (line 232), `gasPrice` is not capped at `tx.gasprice` and `baseGas` is
arbitrary. Any transaction, including a cancellation, can therefore pay out the Safe's whole token
balance.

## Options

### A. Ban refunds
Require `gasPrice == 0`, `gasToken == 0` and `refundReceiver == 0`.
- (+) Closes the channel completely. Nothing to account for.
- (−) No relayer-paid execution.

### B. Count refunds against the outflow cap
- (−) Needs an upper bound on `gasUsed` before execution. More logic on every transaction.

## Decision

**Option A**, enforced in `checkTransaction` on every transaction, including cancellations.

Owner's reasoning: both payment branches (lines 228 and 232) multiply by `gasPrice`, so
`gasPrice == 0` zeroes all refunds. Treasuries execute their own transactions and don't need
relayer refunds.

## Consequences

- R2 (the cancellation always passes) also requires these three fields to be zero.
- The module path has no refund mechanism, so nothing applies there.
