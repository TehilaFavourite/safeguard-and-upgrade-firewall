# ADR 0001: Target Safe v1.5.0

- Status: Accepted
- Date: 2026-10-09
- Pinned dependency: `lib/safe-smart-account` at tag `v1.5.0` (commit `dc437e8`)

## Context

The firewall is a Safe guard whose core claim is that its rules hold even when every
signer has been tricked. A Safe executes transactions through two paths:

1. `execTransaction`, which runs signature checks and then the transaction guard
   (`checkTransaction` before execution, `checkAfterExecution` after).
2. `execTransactionFromModule`, where an enabled module executes with no signatures.

The candidate versions differ in whether path 2 can be guarded at all:

- **v1.4.1:** `ModuleManager.execTransactionFromModule` (`git show v1.4.1:contracts/base/ModuleManager.sol`,
  lines 81-93) checks only that the caller is an enabled module (line 88), then calls `execute` (line 90).
  There is no guard hook.
- **v1.5.0:** adds `IModuleGuard` (`contracts/base/ModuleManager.sol:13-39`), which is called in
  `preModuleExecution` (lines 94-109) and `postModuleExecution` (lines 118-124). It is stored in its
  own slot, `MODULE_GUARD_STORAGE_SLOT`, and set via `setModuleGuard` (lines 258-270).

The transaction guard interface is identical in both versions (interface ID `0xe6d7a83a`).
Guards do not exist before v1.3.0: `checkAfterExecution` first appears in `v1.3.0:contracts/base/GuardManager.sol`
and is absent from v1.2.0 and v1.1.1.

## Options

### A. Target v1.5.0
- (+) Both execution paths can be guarded.
- (+) Current release, audited by Certora and Ackee (see "Audit provenance" below).
- (+) `checkSignatures(executor, ...)` overload (`contracts/Safe.sol:276`) makes signature
  re-verification usable from a guard.
- (−) Most existing Safes run older versions and must migrate their singleton first.

### B. Target v1.4.1
- (+) Longer production history and more existing Safes on this version.
- (−) No module guard. Any enabled module can call `setGuard(0)` and disable the firewall.
  The only mitigation is banning modules, which does not cover modules enabled before the guard
  and excludes legitimate modules (recovery, allowances).

### C. Support both
- (+) Widest compatibility.
- (−) Roughly doubles the test matrix with no new security property. The v1.4.1 limitation remains.

## Decision

Target **Safe v1.5.0** (option A).

Owner's reasoning:

> The project's core claim is that the rules hold even when every signer has been fooled. On v1.4.1
> an enabled module can call setGuard(0) through execTransactionFromModule without my guard ever
> running, so that claim would always need a caveat. v1.5.0 lets me guard both execution paths.
> The cost I accept is that most existing treasuries will need to migrate their singleton before
> they can use this.

## Why the post-execution invariant check works

Both execution paths read the guard address **once, into a local variable, before execution**, and
reuse that local for the post-check:

- `execTransaction` (`contracts/Safe.sol`):
  - line 149: `address guard = getGuard();` (after signature checks at 147, before execution)
  - line 152: `checkTransaction(...)` on that `guard`
  - line 180: `execute(...)`
  - lines 203-204: `checkAfterExecution(txHash, success)` on the **same local** `guard`.
    The guard slot is not re-read.
- `execTransactionFromModule` (`contracts/base/ModuleManager.sol`):
  - line 101: `guard = getModuleGuard();` inside `preModuleExecution`, returned to the caller
  - line 160: the caller stores it in a local
  - line 161: `execute(...)`
  - line 162: the same local is passed to `postModuleExecution`, which calls `checkAfterModuleExecution`
    (line 120).

Consequence: if a delegatecall overwrites `GUARD_STORAGE_SLOT` (or `MODULE_GUARD_STORAGE_SLOT`, or
slot 0) during execution, the **original** guard still runs its post-check in the same transaction
and can revert it.

This only works if the post-check actively inspects state. The cached address guarantees that the
original guard is called; it does not compare anything by itself. `checkAfterExecution` must:

- read the Safe's storage, for example through `getStorageAt` (`StorageAccessible`), because
  `getGuard()` is `internal`;
- compare the singleton, guard, module guard, fallback handler, modules, owners and threshold
  against expected values.

The corollary also holds: the transaction that installs the guard has `guard == address(0)` cached
at line 149, so it gets **no** post-check from our guard.

## Audit provenance

Files in `lib/safe-smart-account/docs/`:

- `audit_1_5_0.md`
- `Safe_Audit_Report_1_5_0_Certora.pdf`
- `Safe_Audit_Report_1_5_0_Ackee.pdf`

Auditors: Certora and Ackee. Neither final audit was performed on the release commit:

| Auditor | Audited commit |
|---|---|
| Certora | `1c8b24a0a438e8c2cd089a9d830d1688a47a28d5` |
| Ackee | `5d26505388e9ee014ad9ac497aa48e3a13426eb1` |

`audit_1_5_0.md` notes "few bugfixes and gas optimization based changes" after each. Cite as
"v1.5.0 was audited by Certora and Ackee at pre-release commits", not "the release commit is audited".

## Consequences

- The guard contract implements both `ITransactionGuard` and `IModuleGuard`, and `supportsInterface`
  returns true for both IDs.
- **Install order** (see `docs/deployment-notes.md`):
  1. Migrate the singleton (a delegatecall to `SafeMigration`).
  2. Install the transaction guard and the module guard.
- **Pre-existing modules** are a trust assumption (see `docs/threat-model.md`). The install script
  fails unless the module list is empty or matches a reviewed list. After install, enabling a new
  module goes through the timelock.
- **Demo scope:** the fork demo replays the Bybit **payload**, re-signed by test owners, after
  migrating the fork's Safe. The claim is "the guard blocks this class of attack", not "this would
  have saved Bybit". Bybit's Safe version must be verified on the fork before relying on this.
- Recovery design is required (separate ADR): a guard that reverts on everything bricks the Safe,
  and a broken module guard also blocks recovery modules.
