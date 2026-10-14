# ADR 0017: Allowlist entry shape and native ETH transfers

- Status: Accepted (amended 2026-10-14)
- Date: 2026-10-14

## Context

The allowlist is keyed by (target, selector). A plain ETH transfer has empty calldata, so it has no
selector. Calldata of 1–3 bytes has an incomplete selector, which Solidity dispatchers route to the
fallback.

## Options

### A. (target, selector, allowValue), with a reserved selector for empty calldata
### B. A separate recipient allowlist for ETH
- (−) A second list and a second code path.

## Decision

**Option A** (owner, 2026-10-14).

- An entry is **(target, selector, allowValue)**, and applies **only** when calldata is at least
  4 bytes.
- **Empty-calldata value transfers** use a separate mapping, `valueRecipient[target]`. *(Amended
  2026-10-14: this replaces the earlier `bytes4(0)` sentinel. A real `0x00000000` selector is an
  ordinary selector entry.)*
- **Calldata of 1–3 bytes** is rejected as malformed.
- **Any `value > 0`** counts against the ETH bucket (ADR 0012), with or without calldata. A call
  with `value > 0` also requires `allowValue == true` on its entry.

## Consequences

- An ETH-only recipient is `valueRecipient[recipient] = true`.
- Adding entries is timelocked, and removing them is immediate (P1, ADR 0002).
- With no `valueRecipient` entry, empty-calldata calls (with or without value) are rejected. That
  matters because they would run the target's `receive` or `fallback` with `msg.sender == SAFE`.

## Problem this resolves: a real selector `0x00000000` collided with the reserved value

`bytes4(0)` is also a valid selector for calldata of 4 bytes or more. Selectors can be brute-forced
to `0x00000000`, and some contracts deliberately use it. If the entry `(target, bytes4(0), …)`
matched both empty calldata and calldata starting with `0x00000000`, allowlisting "ETH to this
contract" would also allowlist an arbitrary function. Candidates:

- calldata of 4 bytes or more whose selector is `0x00000000` is rejected outright, so `bytes4(0)`
  only ever means empty calldata;
- or the entry gets an explicit `emptyCalldata` flag.
