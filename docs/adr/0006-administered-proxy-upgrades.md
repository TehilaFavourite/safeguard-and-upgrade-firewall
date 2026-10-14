# ADR 0006: Administered proxy upgrades are in scope, with a user-exit delay

- Status: Accepted (open questions below)
- Date: 2026-10-09

## Context

A Safe often holds the admin role for upgradeable proxies (protocol contracts). Downstream users
deposit funds behind those proxies. A malicious upgrade therefore harms third parties who never
signed anything. That is higher severity than a loss of the Safe's own funds (threat model A2).

## Options

### A. In scope, with an upgrade delay sized for user exit
- (+) Users get a guaranteed window to see a queued upgrade and leave.
- (−) Slower legitimate upgrades, including emergency fixes.

### B. In scope, with the same delay as guard config changes
- (+) One delay to reason about.
- (−) A delay sized for detection may be too short for users to exit.

### C. Out of scope (the guard protects only the Safe)
- (−) Ignores the highest-severity asset.

## Decision

**Option A.** Administered proxies are in scope.

- Queued upgrades emit public events.
- The proxy-upgrade delay must be at least as long as users need to exit, so it may be longer
  than the delay for config changes.

Owner's reasoning: downstream protocol users depend on the Safe, so a malicious upgrade of an
administered proxy is a third-party threat with higher severity.

## Consequences

- "Upgrade" must cover every way of changing what code runs, or who controls that:
  - `upgradeTo` and `upgradeToAndCall` (UUPS and transparent), including initializer calldata;
  - ProxyAdmin `upgrade` and `upgradeAndCall`;
  - beacon `upgradeTo`, which affects every proxy behind the beacon;
  - admin or ownership handover (`changeAdmin`, `transferOwnership` on a ProxyAdmin, role grants
    such as `DEFAULT_ADMIN_ROLE` / `UPGRADER_ROLE`). These are upgrades by proxy and need the
    same delay.
- The guard must know which (target, selector) pairs are upgrade-class. This is part of the
  allowlist entry, not inferred.
- The delay is per proxy, or at least bounded below by the longest exit time of the proxy's own
  mechanics (withdrawal queues, unbonding periods).
- Storage-layout collision checks (off-chain, with an on-chain approved layout hash) attach to
  the queued upgrade.

## Resolved questions (owner, 2026-10-09)

1. **No emergency upgrade path.** Only power-reducing actions are fast (P1).
2. **A queued upgrade binds** the implementation address, its `extcodehash` and the hash of the
   initializer calldata. All three are re-checked at execute.
3. **The delay is at least the proxy's own withdrawal period.**
4. **Admin transfers, beacon upgrades and role grants count as upgrades.**
