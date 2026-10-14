# ADR 0007: One guard instance per Safe

- Status: Accepted
- Date: 2026-10-09

## Context

The guard holds per-Safe state: config, rolling-window counters, the timelock queue and the
transient reentrancy flag. One instance could serve many Safes (shared), or each Safe could get its
own.

## Options

### A. One guard per Safe, deployed by a factory, Safe address immutable
- (+) A bug or bad config affects one Safe.
- (+) No state keyed by `msg.sender`.
- (+) Simpler to audit.
- (−) One deployment per Safe (gas). The factory becomes part of the trusted setup.

### B. Shared singleton guard, all state keyed by Safe
- (+) One deployment, one place to upgrade.
- (−) Shared blast radius. Every storage access must be keyed by Safe, and a single keying bug
  crosses Safes.

## Decision

**Option A.** One guard per Safe, deployed by a factory, with the Safe address immutable.

Owner's reasoning: limits the blast radius, removes `msg.sender`-keyed state, simpler to audit.

## Consequences

- All four hooks revert unless `msg.sender == safe`. Otherwise anyone could call
  `checkAfterExecution` (or the module equivalents) to corrupt counters or the reentrancy flag.
- Config functions also require `msg.sender == safe`. They must additionally check which
  execution path is active (signed or module), using the transient context set by the pre-hook,
  so modules cannot queue or cancel (threat model §3.3).
- `supportsInterface` returns true for both `ITransactionGuard` and `IModuleGuard`.
- **Deployment (owner, 2026-10-14; resolves the factory front-running item):**
  - **All guard config is passed as constructor arguments**, and there is never an `initialize()`.
    The CREATE2 address therefore commits to the full config.
  - `GuardFactory.deploy(config)` reverts with `NotSafe` unless `msg.sender == config.safe`.
  - Salt = `keccak256(abi.encode(safe, VERSION))`. The address is predicted from
    (safe, version, constructor args), and a different config gives a different address.
  - **No factory-level "one guard per Safe" rule.** A replacement guard (escape path, ADR 0014) is
    a new deployment with its own config.
  - The install batch deploys the guard as its **first** step (`docs/deployment-notes.md`).
- The shared guard is v2 backlog (ADR 0009).
