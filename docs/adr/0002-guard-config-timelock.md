# ADR 0002: Timelock guard configuration changes inside the guard

- Status: Accepted
- Date: 2026-10-09

## Context

The guard's policy (allowlists, caps, delays) lives in the guard's own storage, not the Safe's.
Its admin functions are naturally authorized by `msg.sender == safe`. Any call that originates
from the Safe satisfies that check, including calls that `checkTransaction` never inspects:

- inner calls of an allowlisted `MultiSendCallOnly` batch, which run with `msg.sender == safe`
  (see ADR 0003);
- calls made by code the Safe delegatecalls into (any allowlisted delegatecall target);
- module transactions, if the module guard is unset or misconfigured.

The post-execution check compares Safe storage slots. It does not see guard storage, so a
config rewrite would pass it unnoticed.

## Options

### A. Timelock enforced inside the guard's config functions
Queue a change, execute it after a delay, and allow cancellation.
- (+) Enforced at the point of change, whatever call path reached it.
- (−) Recovery from a bad config takes at least the delay.

### B. `checkTransaction` detects calls to the guard's config functions and blocks or queues them
- (−) Misses every call path the pre-check never sees (listed above).

### C. External timelock contract owns the guard's config
- (+) Reuses an audited timelock (e.g. OpenZeppelin `TimelockController`).
- (−) Adds a second contract and admin model to secure, and the same path question applies to
  whoever can propose to it.

## Decision

**Option A.** Guard config changes are timelocked inside the guard's own config functions
(queue → execute after delay, with cancel).

Owner's reasoning: there are call paths the pre-check never sees, so the rule has to live at the
function itself.

## Consequences

- *(Amended 2026-10-14, owner.)* **Power-adding** config changes are timelocked. **Power-reducing**
  changes take effect immediately through the signed path (P1). Examples: lowering a cap
  (ADR 0012), raising a proxy's withdrawal period (ADR 0011), cancelling a queued item. The
  initial configuration at deployment is the only other immediate change.
- Queuing still requires `msg.sender == safe`. An attacker who tricks the signers can queue a
  malicious change, so the timelock only helps if someone is watching. Monitoring and alerting on
  `Queued` events is part of the design, not an extra.
- **Open questions** (separate decisions):
  - Who can cancel, and should cancelling be cheaper than queuing?
  - What is the delay?
  - Can the delay itself be changed, and is that change timelocked under the old delay?
  - How does this interact with recovery from a guard that blocks everything?
- Replacing or removing the guard (`setGuard`) is a Safe self-call, not a guard config call. It is
  covered by the self-call timelock rule and the post-execution slot check, not by this ADR.
