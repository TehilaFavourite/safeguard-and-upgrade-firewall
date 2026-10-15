# Build Plan (v1)

Each phase follows the workflow in `docs/engineering-principles.md`. The design is in
`docs/v1-spec.md`, `docs/threat-model.md` and `docs/adr/`.

## Target layout

Propose changes before deviating from this.

```
src/
  SafeFirewallGuard.sol        ITransactionGuard + IModuleGuard + ERC165; hooks, config entry points
  GuardFactory.sol             CREATE2 deploy, one guard per Safe, Safe address immutable (ADR 0007)
  InstallChecker.sol           module-list hash check used in the atomic install batch
  libraries/
    MultiSendDecoder.sol       strict parser (ADR 0003)
    CallClassifier.sol         self-call, approval, revocation, transfer, proxy upgrade, other
    PolicyEngine.sol           the pre-check pipeline from the spec, applied to each call
    TokenBucket.sol            ADR 0012
    TimelockQueue.sol          queue/execute/cancel/expiry, delay classes (ADR 0002, 0008, 0011)
    SafeSlots.sol              slot constants + snapshot/compare helpers
    TransientTokenMap.sol      keyed transient map + bounded token list; assembly exception 1 (ADR 0005)
    MemoryReader.sol           read-only bounds-checked field reads; assembly exception 2 (ADR 0005)
  interfaces/
test/
  base/FirewallTestBase.sol    abstract; _deploySafe() hook (ADR 0013)
  base/LocalSafe.t.sol, base/ForkSafe.t.sol
  unit/, fuzz/, invariant/, fork/
  mocks/                       Bybit-shaped delegatecall target, non-standard tokens, malicious module
script/
  DeployGuard.s.sol, InstallBatch.s.sol, ScanApprovals (off-chain approval scan)
bot/                           alert bot (Phase 12)
```

`TransientTokenMap.sol` is an addition to the original layout, following ADR 0005.

## Core flow

**Pre-hooks** (`checkTransaction`, `checkModuleTransaction`), in this order (ADR 0014):

1. revert unless `msg.sender == SAFE`;
2. reentrancy check, using a transient flag shared across all four hooks (ADR 0005);
3. record the active path (signed or module) in transient storage;
4. refund fields must be zero (ADR 0010);
5. **R1:** escape-path items return immediately, before any policy code. This covers queue,
   execute and signer-cancel, in the exact shape from ADR 0014. On the module path, escape and
   config calls are rejected;
6. **R2:** the exact cancellation transaction always passes;
7. reject every other call to `GUARD` (ADR 0018). This comes after R1, because escape calls are
   calls to `GUARD`;
8. require `masterCopy() == expectedSingleton` (ADR 0020);
9. snapshot the protected slots into transient storage;
10. run the policy pipeline on the call, or on every inner call of a strictly decoded
   `MultiSendCallOnly` batch, accumulating per-token outflow in the transient token map.

**Post-hooks**, in this order:

1. R1 fast return, which still clears the transient state it set;
2. compare the protected slots against the snapshot. A change is allowed only when a matured queued
   item authorized it in this transaction;
3. if `success == true`, settle and debit the token buckets, and revert if a total exceeds the
   level;
4. clear transient state.

**Config functions:**

- Callable only by `SAFE` on the signed path (checked against the transient path flag).
- Power-adding changes are timelocked by delay class.
- Power-reducing changes are immediate, and cancel pending power-adding items for the same key (P1).
- Guardian cancel rights are exactly as in ADR 0008.
- Items expire 14 days after their ETA.

## Phases

- **0. Traceability.** `docs/test-plan.md` maps every requirement in `v1-spec.md` and every
  threat-model mitigation to a planned test name, and flags any requirement with no test.
- **1. Skeleton and harness.** Interfaces, an empty guard, the factory, `FirewallTestBase` with
  both Safe sources, the caller check, the reentrancy flag and path tracking.
- **2. Bybit stopper.** Candidate for the owner to accept or reject in the Phase 2 invariant
  proposal: return a real hash of the module call parameters from `checkModuleTransaction`, store
  it in transient storage, and check it in `checkAfterModuleExecution`.
  - Delegatecall policy: on the signed path only the pinned `MultiSendCallOnly`; on the module
    path never.
  - Refund ban, R2 cancellation, protected-slot snapshot and compare.
  - Separate tests proving that the pre-check alone **and** the post-check alone each stop a
    Bybit-shaped payload.
  - ⚠️ **Not deployable before Phase 10:** the allowlist, timelock and caps are not yet in place.
    This replaces the Phase 2-3 interim warning, which is resolved: since Phase 3, batch inner
    calls get the same pre-check as top-level calls.
- **3. MultiSend decoder.**
  - Strict parsing; `to == 0` normalized to the Safe; plain `MultiSend` rejected.
  - Fuzzing with malformed batches.
  - A differential test showing that every batch the decoder accepts is executed identically by
    `MultiSendCallOnly`.
- **4. Timelock and config.**
  - Queue, execute, cancel and expiry; delay classes.
  - The R1 escape path in both hooks (ADR 0014), and guardian rules.
  - P1 immediate reductions cancelling pending raises.
- **5. Self-call policy.**
  - `setGuard`, `setModuleGuard`, `enableModule`/`disableModule`, owners and threshold, and
    `setFallbackHandler`, all through the timelock.
  - Module-path parity: the same pipeline and shared counters; modules can't queue or cancel.
- **6. Target/selector allowlist** with parameter constraints (for example fixed recipients),
  deny by default (P2).
- **7. Outflows.** Incident response must stay a single call without batching (ADR 0023, D3), so
  the guard needs multi-key power-reducing functions, for example `lowerCaps(tokens[], caps[])`.
  Each reduction advances the key epoch (ADR 0023, D6).
  - ETH and ERC-20 transfers.
  - Approvals: counted in full; unlimited approvals rejected; exact revocations always pass;
    `setApprovalForAll` hard reject; Permit2 never allowlisted.
  - Token bucket, including settling before a cap change.
  - The 8-token transient limit.
  - Non-standard tokens: no return value, fee-on-transfer, reverting on zero.
- **8. Administered proxy upgrades.**
  - `upgradeTo`/`upgradeToAndCall`, admin transfers, beacon upgrades and role grants.
  - Queued items bind the implementation address, its `extcodehash` and the initializer calldata
    hash, all re-checked at execute.
  - Withdrawal-period rules (ADR 0011).
  - Singleton migration item (ADR 0015).
- **9. Install.**
  - Factory, `InstallChecker`, and the `InstallBatch` script: module-list check → revoke approvals
    from the scan → `setGuard` → `setModuleGuard`. Migration is a separate transaction before the
    batch.
  - The approval scan script.
  - A test that the batch is atomic.
- **10. Stateful invariant suite.** A handler randomly mixes signed transactions, module
  transactions, batches, config changes and time warps. Global invariants, at minimum:
  - protected slots never change without a matured item;
  - outflow per token never exceeds the documented bound;
  - the escape path is always executable after its delay;
  - the cancellation transaction always passes.
- **11. Fork demo.**
  - Verify Bybit's Safe version and pre-hack state.
  - Migrate, install, then replay the malicious payload signed by test owners, which reverts.
  - Then run a legitimate proxy upgrade through the timelock, which succeeds.
  - Runnable with one command and readable as a demo.
- **12. Alert bot** (Rust, alloy). Two sources: guard events, and failed transactions to the Safe,
  re-run with `eth_call` at the parent block and decoded against the guard's custom errors.
  - Alerts on: `Queued` (with countdown), blocked transactions (from decoded reverts), cap
    near-exhaustion, guardian actions and expiry.
  - Config through environment variables; a dry-run mode against the fork.
- **13. Finish.**
  - README: problem, Bybit walkthrough, architecture diagram, design principles, threat-model
    summary, known limitations, how to run the tests and the demo, gas report.
  - CI workflow, two jobs (ADR 0013):
    - **unit:** fmt, build, the unit-variant tests (parallel), coverage, `forge snapshot --check`
      and Slither, on every push, with no secrets;
    - **fork:** `forge test -j 1` on the fork variant, with the `ETH_RPC_URL` secret, on PRs to
      `main` and nightly.
  - A final pass checking that every ADR matches the code.
