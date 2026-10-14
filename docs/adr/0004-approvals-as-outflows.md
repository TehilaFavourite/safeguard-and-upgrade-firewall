# ADR 0004: Treat token approvals as outflows at approval time

- Status: Accepted (open questions below)
- Date: 2026-10-09

## Context

An approval moves no funds when it executes. The spender later calls `transferFrom` from their own
account. That call never goes through the Safe, so neither `checkTransaction` nor
`checkAfterExecution` sees it. If approvals don't count as outflows, an attacker who tricks the
signers into one approval can drain the Safe past every cap.

## Options

### A. Count approvals against the outflow cap at approval time
- (+) Enforced at the last point where the guard has control.
- (−) Conservative: an approval that is never spent still uses up cap.

### B. Block all approvals
- (−) Breaks most DeFi interaction.

### C. Ignore approvals and count only direct transfers
- (−) Trivially bypassable.

## Decision

**Option A**, with these rules:

- `approve` counts against the outflow cap at approval time.
- Unlimited approvals are always rejected.
- The spender must be allowlisted.
- `increaseAllowance` and `setApprovalForAll` are treated the same way.
- `SignMessageLib` is not an allowlisted delegatecall target, because an off-chain permit signed by
  the Safe is also a deferred outflow.

Owner's reasoning: the guard never sees the later `transferFrom`, so approval is the last point
where it has control.

## Consequences

- The policy pipeline needs decoders for approval selectors:
  - `approve` `0x095ea7b3`
  - `increaseAllowance` `0x39509351`
  - `setApprovalForAll` `0xa22cb465`

  Because the (target, selector) allowlist is default-deny, the main risk is **allowlisting a
  function that is an approval in disguise**. Examples: Permit2 `approve`, ERC-777
  `authorizeOperator`, protocol-specific "delegate" or "operator" setters. Reviewing a selector
  before allowlisting it must include the question "does this grant a third party the right to
  move funds later?"
- Composes with ADR 0003: approvals inside a batch count toward the same running total.

## Resolved questions (owner, 2026-10-09)

1. `setApprovalForAll(op, true)` is a **hard reject** in v1, with no dormant operator-allowlist
   code (owner, 2026-10-14). NFT marketplace use is out of scope (ADR 0009). An operator allowlist
   is v2 backlog. `setApprovalForAll(op, false)` is a revocation and always passes (item 2).
2. Exact-match revocations always pass and are not counted (P1). That means `Call`, `value == 0`,
   and `approve(_, 0)` or `setApprovalForAll(_, false)`.
3. The new allowance counts in full. Conservative, and no trust in token code.
4. Caps are per token, with no oracle.
5. v1: Permit2 is never an allowlisted spender, so off-chain Permit2 signatures move nothing.
   Other EIP-1271 uses are a documented limitation. v2: a restrictive fallback handler that only
   honours messages approved through a guarded transaction.

6. **Allowances granted before install** (A3), for example an unlimited Permit2 approval, would
   still let off-chain signatures move funds. Resolution:
   - An off-chain script scans the Safe's historical `Approval` events into a reviewed
     (token, spender) list.
   - The install batch **revokes** every pair on it. This only reduces power, so it is safe to
     repeat (P1).
   - Permit2 is revoked explicitly on every held token. Revoking the ERC-20 allowance to Permit2
     also neutralizes every allowance held inside Permit2.
   - Allowances the scan can't find (tokens that don't emit `Approval`) are a documented trust
     assumption.
7. **Tokens that revert on `approve(_, 0)`** (owner, 2026-10-14):
   - The approval scan script dry-runs every revocation on a fork.
   - Tokens that revert are revoked with `approve(spender, 1)` instead, leaving a residual
     allowance of 1 base unit. They are listed in `docs/deployment-notes.md`.
   - Specific tokens (for example BNB) are verified on the fork, not assumed.

   **Consequence after install:**
   - The exact-match revocation rule (item 2) covers `approve(_, 0)` only.
   - For these tokens, revoking during an incident means `approve(spender, 1)`, which is an
     ordinary approval: it needs an allowlisted spender and counts 1 against the cap.
   - **Resolved (owner, 2026-10-14):** `approve(spender, 0)` **and** `approve(spender, 1)` skip
     the spender allowlist. Amount 1 still counts against the bucket, which covers tokens with 0
     decimals, where 1 unit can matter. `approve(_, 0)` is still not counted (item 2).

## Original open questions

1. **`setApprovalForAll` has no amount.** Under "unlimited approvals are always rejected" it is
   always rejected, which rules out NFT marketplace use. Confirm this is intended.
2. **Revocations.** `approve(spender, 0)` and `setApprovalForAll(op, false)` should always pass
   and not count against the cap, so approvals can be revoked during an incident. Confirm.
3. **What counts.** `approve` replaces the allowance, so count the new amount in full (simple,
   conservative) or the increase over the current allowance (needs an `allowance()` read and
   trust in the token's implementation)?
4. **Units.** Is the cap per token, or in a common unit (needs a price source, which is a new
   trust assumption)?
5. **Off-chain EIP-1271 approvals bypass this ADR.**
   `CompatibilityFallbackHandler.isValidSignature` (`contracts/handler/CompatibilityFallbackHandler.sol:78-84`)
   validates any message for which owners provide threshold signatures. It calls
   `safe.checkSignatures(address(0), messageHash, _signature)` with no Safe transaction, so no guard
   runs. Tricked signers can sign Permit2 transfers or other 1271-based authorizations entirely
   off-chain. Excluding `SignMessageLib` closes only the on-chain `signedMessages` path
   (line 79). Needs its own ADR. Candidate mitigations:
   - a restrictive fallback handler;
   - accept the risk and document it;
   - bounded Permit2 allowances.
