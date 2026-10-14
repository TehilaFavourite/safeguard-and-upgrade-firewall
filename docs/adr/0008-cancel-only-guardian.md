# ADR 0008: Cancel-only guardian for queued changes

- Status: Accepted
- Date: 2026-10-09

## Context

A timelock only helps if someone acts during the delay. If a malicious upgrade or config change is
queued (through social engineering, or a compromised UI during queuing), cancelling it through the
Safe needs threshold signatures. Those are the same signers who were just tricked, and they may be
slow to gather.

## Options

### A. Cancel-only guardian role
A separate address that can cancel queued items, and do nothing else.
- (+) Fast response without a threshold.
- (−) A rogue guardian can grief by cancelling legitimate items.

### B. Cancellation only through a signed Safe transaction
- (−) Slow, and relies on the signers who were just deceived.

### C. A guardian with broader powers (pause, veto, execute)
- (−) Adds power, which violates P1. A compromised guardian becomes an attacker.

## Decision

**Option A.** Cancelling only reduces power (P1). A rogue guardian can only grief, and signers
remove it through the timelock.

## Consequences

- The guardian calls the guard directly, with its own authorization (`msg.sender == guardian`).
  It cannot execute, queue or change config.
- The guardian is part of the alerting setup: the alert bot notifies the guardian.

## Cancel rights (owner, 2026-10-09)

- **The guardian** can cancel any queued item **except**:
  - escape-path items (guard removal or replacement);
  - guardian removal or replacement.
- **Signers** (signed path only) can cancel everything, including escape items. Signer-cancel sits
  in the minimal R1 code path.

Owner's reasoning: a rogue guardian can't block its own removal or keep the Safe frozen. A malicious
escape item queued by fooled signers is cancelled by the signers after the monitoring alert.

Worst case with a rogue guardian: it griefs ordinary items. Signers remove it in 48h (ADR 0011),
and it cannot cancel that removal.

## Problem this resolves: a griefing guardian could make a freeze permanent

The reasoning "a rogue guardian can only grief" breaks down if the guardian can cancel:

- **its own removal**, which signers queue through the timelock; or
- **guard removal or replacement**, the escape path (R1).

A rogue guardian could cancel both forever. The Safe would then be stuck with a guard it can't
remove and a guardian it can't fire, which violates "a bounded freeze is acceptable, a permanent
one is not". The owner must decide a rule before tests are written. Candidates:

- The guardian cannot cancel guardian-removal or escape-path items.
- Or a cancelled item can be re-queued with a flag the guardian cannot cancel.
