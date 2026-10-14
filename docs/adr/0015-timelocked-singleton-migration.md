# ADR 0015: Timelocked singleton migration

- Status: Accepted
- Date: 2026-10-14

## Context

The delegatecall policy allows only `MultiSendCallOnly` (ADR 0003). `SafeMigration` only runs via
delegatecall (`contracts/libraries/SafeMigration.sol:45-46`), so a future singleton migration is
impossible while the guard is installed. "Remove the guard, migrate, reinstall" opens an unguarded
window.

## Options

### A. A timelocked migration item, executed while the guard stays installed
### B. Escape path: remove the guard (72h), migrate, reinstall
- (−) An unguarded window between removal and reinstall.

## Decision (owner, 2026-10-14)

**Option A.** Owner's reasoning: no unguarded window, ever.

- The migration is exactly **one top-level `DelegateCall`** to the migration contract.
- **Bound per item at queue time** (owner, 2026-10-14):
  - the migration contract address and its `extcodehash`;
  - the calldata hash;
  - the expected resulting singleton address and its `extcodehash`.

  The guard does **not** pin a `SafeMigration` at construction.
- **Allowed calldata:** v1 allows only `migrateSingleton()`. A fallback handler change is its own
  timelocked item.
- **Delay:** escape class (72h).
- **Post-check:** accepts a slot 0 change **only** to the bound singleton, whose `extcodehash` is
  re-checked, and **only** if both guard slots still point at this guard.

## Consequences

- **The migration contract's code is the trust boundary.** It runs by delegatecall in the Safe's
  storage, so it can write **any** slot, not only the protected ones. Examples: `nonce`,
  `approvedHashes`, `signedMessages` (`contracts/libraries/SafeStorage.sol`). A `signedMessages`
  entry would make the Safe validate an EIP-1271 signature with no guard involved (ADR 0004,
  item 5). The bound `extcodehash` plus review during the 72h delay is the only control over what
  the migration contract writes. This is a trust assumption.
- **Behaviour of the new singleton.** The post-check verifies slots, not behaviour. A future
  singleton that, for example, stops calling the module guard would weaken the firewall with
  every slot intact. This is also a review-during-delay trust assumption.

## Problem this resolves: one pinned `SafeMigration` can only migrate to v1.5.0

A `SafeMigration` deployment's target is fixed at construction:

- `SAFE_SINGLETON` is an immutable set in the constructor (`SafeMigration.sol:25, 56-65`);
- `migrateSingleton()` writes exactly that value (lines 71-73).

The canonical mainnet `SafeMigration` (`0x6439e7ABD8Bb915A5263094784C5CF561c4172AC`, `CHANGELOG.md`)
targets **v1.5.0**, which a guarded Safe already runs. Pinning that address as a constructor
immutable (ADR 0013) would make this item usable only to "migrate" to the current version. A real
future migration (for example to v1.6) needs a **different** `SafeMigration` deployment that does
not exist yet.

Candidates considered:

- **Bind the migration contract per item.** The queued item records the migration contract's
  address and `extcodehash`, as well as the target singleton. The guard does not pin
  `SafeMigration` at construction. The 72h delay and the alert bot are the review window for the
  new contract.
- **Pin a reviewed codehash, not an address.** The guard stores the expected runtime codehash
  pattern. This doesn't work directly: immutables are embedded in runtime code, so every
  `SafeMigration` deployment has a different codehash.

## Points settled with the decision

- **Allowed selector:** only `migrateSingleton()`. `migrateWithFallbackHandler()` also calls
  `setFallbackHandler` (`SafeMigration.sol:80-82`), which changes the fallback handler slot. A
  fallback handler change is its own timelocked item instead. The L2 variants (`migrateL2*`) are
  out of scope on mainnet (ADR 0009).
- **Behaviour of the new singleton:** a trust assumption, reviewed during the delay (see
  Consequences).
