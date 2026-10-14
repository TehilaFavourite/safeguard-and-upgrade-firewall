# ADR 0011: Timelock delay values

- Status: Accepted
- Date: 2026-10-09

## Context

ADRs 0002, 0006 and 0008 introduce timelocked items, but none of them set values. Delays trade
detection time against how long legitimate changes take, and for the escape path against the
worst-case freeze (threat model §2, R1).

## Options

- **A. Fixed per-class delays, immutable in v1.**
- **B. Configurable delays, where changing a delay is itself timelocked.**
  (−) Lowering a delay adds power, so every change has to be reasoned about against the old delay.
- **C. One delay for everything.**
  (−) Can't satisfy both "short worst-case freeze" and "long enough for proxy users to exit".

## Decision

**Option A.**

| Item class | Delay |
|---|---|
| Config changes | 48h |
| Escape path (guard removal or replacement) | 72h, which is the worst-case freeze under R1 |
| Proxy upgrades (ADR 0006) | `max(7 days, proxy withdrawal period + 24h)` |
| Guardian changes | 48h |

- Delays are immutable in v1 and set at deploy, because lowering a delay would add power.
- Queued items expire 14 days after their ETA.

## Consequences

- Worst-case freeze is 72h (escape path), as long as signers can still use the signed path.
- Expiry stops stale items from being executed long after the context that justified them.
- Changing a delay means deploying a new guard, which goes through the 72h escape path.

## Proxy withdrawal period changes (owner, 2026-10-10)

- **Raising** a proxy's withdrawal period is a normal 48h config change. It lengthens the delay,
  so it only reduces power (P1).
- **Lowering** it takes effect only after the proxy's **current** upgrade delay has passed. A 48h
  change can never shorten a long exit window.
- **Raising cancels pending lowerings.** A power-reducing change to a key (here, raising a proxy's
  withdrawal period, which lengthens its upgrade delay) cancels every pending power-adding change
  to that same key, including a pending lowering of the period. This is the same rule as ADR 0012
  (P1).

## Problem this resolves: the proxy withdrawal period is config

The proxy-upgrade delay depends on each proxy's withdrawal period. If registering a proxy or
changing its withdrawal period is an ordinary 48h config change, then a 48h change can lower a
proxy's exit delay, for example from 31 days to 7. That defeats ADR 0006. Candidates:

- the withdrawal period is fixed when the proxy is registered and can never be lowered;
- or lowering it is delayed by the proxy's *current* upgrade delay.
