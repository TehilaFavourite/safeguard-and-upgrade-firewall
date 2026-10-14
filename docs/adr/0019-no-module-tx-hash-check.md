# ADR 0019: No module transaction hash check (considered and rejected)

- Status: Rejected
- Date: 2026-10-14

## Context

`checkModuleTransaction` returns a `bytes32`. The Safe passes it back unchanged to
`checkAfterModuleExecution` (`lib/safe-smart-account/contracts/base/ModuleManager.sol:107, 120`).
A guard could return a hash of the module call's parameters, store it in transient storage, and
check in the post-hook that the same hash comes back.

## Options

### A. Return and check a real hash
Return `keccak256(abi.encode(to, value, keccak256(data), operation, module))`, store it, and revert
with `ModuleTxHashMismatch` in the post-hook if it differs.

### B. Return a constant and don't check it

## Decision

**Option B** (owner, 2026-10-14). The guard returns `NO_MODULE_TX_HASH`.

Owner's reasoning: the Safe returns exactly the hash we gave it, so a mismatch could only come from
an out-of-turn hook call. Out-of-turn calls are already covered by:

- **ADR 0018**, which rejects any Safe call to the guard's hook selectors. This is the real control.
- **Path pairing**, where a post-hook reverts with `NoActiveExecution` unless a matching pre-hook
  is active (Phase 1 invariant I1.9).

## Consequences

- Less code and no extra transient state on the module path.
- If a future requirement needs a per-execution identifier (for example for events), revisit this
  ADR rather than adding a hash ad hoc.
