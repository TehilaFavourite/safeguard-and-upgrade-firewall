# Threat Model (v1)

## 1. System overview

A per-Safe guard (ADR 0007) for Safe v1.5.0 (ADR 0001). It implements both `ITransactionGuard` and
`IModuleGuard`, so policy runs on both execution paths:

- **Pre-checks** enforce policy before execution. They decode `MultiSendCallOnly` batches
  (ADR 0003) and run every call through the same pipeline.
- **Post-checks** verify Safe invariants and record outflows (ADR 0005).
- **Changes that add power** go through a timelock (ADR 0002, ADR 0006). A cancel-only guardian
  and an alert bot watch the queue (ADR 0008).

### Principles

- **P1:** An action may be fast only if it reduces power (cancel, revoke, pause) **and** cannot
  reduce the signers' ability to reach the threshold. Anything else goes through the timelock
  (ADR 0016).
- **P2:** Deny by default. Unconfigured tokens have cap 0. Unlisted targets and operators are rejected.

## 2. Assets being protected

Ranked from highest to lowest priority.

| ID | Asset | Includes |
|---|---|---|
| A1 | Control | Owners, threshold, singleton (slot 0), guard and module guard, fallback handler, modules. The guard's config **and bookkeeping** (rolling-window counters, timelock queue). The **escape and cancellation paths**. |
| A2 | Administered proxies | Implementation and admin slots, and the third-party funds behind them. |
| A3 | Safe-held funds | ETH, ERC-20 tokens, and allowances already granted. |
| A4 | Liveness | The ability to execute ordinary legitimate transactions. |
| A5 | Signature authority | The Safe's EIP-1271 signature, which can authorize off-chain actions with no Safe transaction. |

**Ranking: A1 > A2 > A3 > A4.**
- Losing control loses everything else permanently, while a cap bounds a fund loss.
- Proxies rank above Safe funds because the value behind them is third-party funds.
- The escape and cancellation paths carry A1 priority even though they are a form of liveness.

### Liveness vs. safety

A bounded freeze is acceptable; a permanent freeze is not. The maximum acceptable freeze equals the
timelock delay, because the escape route goes through it.

**Trade-off:** a longer delay gives more detection time but a longer worst-case freeze.

- **R1 (minimal escape path).** The guard removal or replacement path is handled at the start of
  **both** hooks, pre-check and post-check, for both the queue and the execute transaction. It runs
  after only the caller check, the reentrancy flag, the path flag and the refund-field check, and
  returns before any policy code (allowlists, caps, MultiSend parser) runs. An escape-path
  transaction is exactly one top-level call, and on the module path escape and config calls are
  rejected (ADR 0014). The post-check matters
  because the *old* guard's post-check runs on the removal transaction (address cached at
  `Safe.sol:149`).
- **I4.20 (critical): an escape target must be bound to this Safe.** If a replacement guard bound
  to a *different* Safe were installed, every transaction, escape and cancellation included, would
  revert with `NotSafe`. That is a **permanent freeze**. Rules (ADR 0023):
  - at `queueEscape` **and** at escape execution, for `x != 0`: a STATICCALL to `x.SAFE()` must
    return this Safe, and `x.supportsInterface` must return true for both guard interfaces.
    Otherwise the call reverts with `EscapeTargetNotBound(x, reportedSafe)`;
  - removal (`x == 0`) is always allowed;
  - **v1 replacements must be this guard type, or removal.**

  A replacement with a wrong `expectedSingleton` is **not** rejected. It fails closed in a
  recoverable way: its R1 and R2 still work, because they run before its step-8 check.
- **R2 (cancellation always passes).** A top-level `Call` to the Safe itself always passes if it
  has:
  - `value == 0` and empty data;
  - `gasPrice == 0`, `gasToken == 0` and `refundReceiver == 0` (ADR 0010).

## 3. Attacker capabilities

### 3.1 Compromised UI / transaction display (Bybit model)

Signers see a harmless transaction but sign attacker-chosen calldata.

- **Stopped:** every on-chain rule still holds. With a strict recipient allowlist, direct theft is
  blocked.
- **Gets through:** allowlisted contracts with attacker-chosen parameters, for example a DEX router
  whose `recipient` the attacker sets.
  - Max loss per window = the sum of per-token caps through those routes.
  - Rule: constrain such parameters in the allowlist entry, or don't allowlist the contract.
- **Raising caps** is a timelocked, visible config change (ADR 0002).

### 3.2 Compromised signer keys (below threshold)

- A single key cannot execute anything new alone.
- **It can:**
  - execute transactions that are already fully signed, and choose when;
  - add its own approval automatically as the executor (`Safe.sol:328`).
- It makes 3.1 easier by one signer.
- Refunds are banned (ADR 0010), so gas parameters give it nothing.

### 3.3 Malicious module

- The module guard runs the **same** pipeline as the transaction guard and shares the same outflow
  counters.
- Modules may never `DelegateCall`.
- Modules may not queue or cancel config changes (signed path only, ADR 0007).
- **Limitation:** module transactions need no signatures. A malicious trusted module can drain
  continuously at the cap rate until someone detects it.

### 3.4 Malicious upgrade proposal

- A queued upgrade binds the implementation address, its `extcodehash` and the hash of the
  initializer calldata, all re-checked at execute. The delay is at least the proxy's withdrawal
  period, and there is no emergency path (ADR 0006).
- During the delay, the **guardian** cancels (ADR 0008), alerted by the alert bot.
- A timelock with nobody watching is only a delay (see §6).

### 3.5 Threshold raise as a freeze attack

- **Attack:** a compromised UI gets the signers to raise the threshold to N-of-N. With a single
  lost or unavailable key afterwards, no transaction can reach the threshold again. That includes
  the escape path and the cancellation, so the freeze is permanent and breaks R1.
- **Mitigation:** every threshold and owner change is timelocked, never fast (ADR 0016). The alert
  bot flags it, and the guardian or signers cancel during the delay.
- **Residual risk:** if nobody acts during the delay, the change executes (monitoring trust
  assumption, §6).

## 4. In scope (v1, ADR 0009)

- Ethereum mainnet
- ETH and ERC-20
- One guard per Safe
- Administered proxies (ADR 0006)
- The alert bot
- The Bybit fork demo

## 5. Out of scope (v1)

- NFTs: every `setApprovalForAll(op, true)` is rejected
- A restrictive fallback handler
- L2s
- A shared guard
- Oracle-based caps

## 6. Trust assumptions

- **Pre-existing modules are trusted.** The install batch's on-chain checker reverts unless the
  module list matches a reviewed hash. After install, enabling any new module goes through the
  timelock.
- **Monitoring.** The alert bot runs, and the guardian responds within the delay. Without this the
  timelock is only a delay.
- **Allowlist review.** Every allowlisted (target, selector) has been reviewed for attacker-chosen
  parameters and for hidden approval semantics (ADR 0004).
- **Pre-existing allowances.** The install batch revokes every (token, spender) pair found by
  scanning `Approval` events (ADR 0004). Allowances on tokens that don't emit `Approval` are not
  found and are trusted.
- **Guardian.** A rogue guardian can only grief ordinary items. It cannot cancel escape-path items
  or its own removal (ADR 0008).
- **Factory and deployment.** The guard factory and the deployed guard bytecode are the reviewed
  versions.

## 7. Known attack paths and mitigations

| Attack path | Mitigation |
|---|---|
| Batch inner calls skip the pre-check | Strict decoding, normalize `to = 0` to the Safe, pinned `MultiSendCallOnly` (ADR 0003) |
| Blocked transaction stays signed | Same-nonce cancellation (`docs/runbook.md`) |
| Deferred outflows via approvals | Counted in full at approval time; unlimited approvals rejected; allowlisted spenders only (ADR 0004) |
| Nested execution vs. caps | Transient-storage reentrancy flag shared by all four hooks (ADR 0005) |
| Gas refunds as an outflow | Banned (ADR 0010) |
| Direct writes to guard slots via delegatecall | Post-check on the cached guard (ADR 0001) |
| Replaced singleton lies through the Safe's getters | Singleton read first via the proxy's `masterCopy()` (ADR 0020) |
| Anyone calls the hooks directly | Hooks revert unless `msg.sender == safe` (ADR 0007) |
| Threshold raise freezes the Safe | Owner and threshold changes timelocked (ADR 0016) |

## 8. Known limitations

- **Demo scope.** Guards do not exist before Safe v1.3.0. The Bybit Safe ran v1.1.1 (verified on-chain,
  ADR 0013). The fork migrates it and replays the same malicious payload, signed by test owners.
  The claim is "the guard blocks this class of attack", not "this would have saved Bybit".
- **Off-chain EIP-1271 signatures** other than Permit2 are not controlled
  (`CompatibilityFallbackHandler.sol:78-84`). The restrictive fallback handler is v2.
- **Cap-rate drain by a trusted module** until detected (§3.3).
- **Allowlisted routes with free parameters** leak up to the caps (§3.1).
- **EIP-7702: an EOA today can have code tomorrow (for Phase 6).** Since EIP-7702, an EOA can
  install a delegation designator and execute code. An allowlisted recipient that is an EOA when it
  is allowlisted can later gain code: its `receive`/`fallback` could re-enter, consume gas, or route
  funds elsewhere. Seen in practice: Foundry's `makeAddr("alice")` address has a 7702 delegation on
  mainnet that forwards ETH (found in Phase 3). **The guard must never rely on a recipient being
  code-free.** The Phase 6 allowlist design must address it, for example by requiring every
  property it relies on to hold even if the recipient has code, and never using `extcodesize` as a
  security check.
- **Module list bound.** Every guarded execution reverts with `TooManyModules` on a Safe with more
  than 16 modules. The state is prevented at install and when queueing `enableModule`. Escape (R1)
  and cancellation (R2) return before the module read, so even a Safe over the limit can't be
  permanently frozen (ADR 0020).

- **Half-executed escape (accepted, fails closed; owner, 2026-10-15).** An escape takes two Safe
  transactions in a fixed order: `setModuleGuard(x)`, then `setGuard(x)` (ADR 0014). If only the
  first runs and the item is then cancelled or expires, the Safe keeps module guard `x` and
  transaction guard = this guard. Nothing becomes reachable that the signers did not approve: `x`
  passed the 72h delay and the I4.20 binding checks, and signed transactions still get this
  guard's full pipeline. Recovery is a 72h escape back to this guard (`docs/runbook.md`).
  Prevention is v2 (`docs/v1-spec.md`).

## 9. Open questions

See the v1 open items in `docs/v1-spec.md`.
