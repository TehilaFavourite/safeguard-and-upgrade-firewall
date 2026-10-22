# ADR 0022: Compile with the optimizer on (200 runs)

- Status: Accepted
- Date: 2026-10-15
- Effective: before Phase 4

## Context

Through Phase 3 the project compiled with the optimizer off (the Foundry default). Safe ships its
audited v1.5.0 contracts with the optimizer **disabled** (`lib/safe-smart-account/CHANGELOG.md:17`).
Our contract sizes grow with every phase, and `GuardFactory` embeds the guard's entire init code
for `new`, so the factory reaches EIP-170's 24,576-byte runtime limit before the guard does.

## Measurements (Phase 3 code)

| | Optimizer off | **Optimizer on, 200 runs** |
|---|---|---|
| `SafeFirewallGuard` runtime | 11,429 B | **6,883 B** |
| `GuardFactory` runtime | 14,964 B | **8,669 B** |
| Both hooks, signed tx (fork; mainnet Safe unchanged) | 68,874 gas | 56,675 gas |
| Pre-check, 3-entry batch (fork) | 66,151 gas | 53,008 gas |
| Decoder alone, 32 entries | 301,425 gas | 167,527 gas |

## Options

### A. Optimizer off
- (+) Matches how Safe ships its audited code.
- (+) Bytecode maps more directly to the source.
- (−) About 40% larger, which puts the factory at risk under EIP-170 as Phases 4–8 add code.

### B. Optimizer on, 200 runs
- (+) About 40% smaller and 18–20% cheaper per guarded transaction.
- (−) Optimizer passes have had bugs (see the known-bugs check below).

## Decision

**Option B**, optimizer on with `runs = 200`, effective before Phase 4 (owner, 2026-10-15).

Owner's reasoning: size is the binding constraint, because the factory embeds the guard's init code
under EIP-170. Gas per transaction is cents either way.

## Conditions, and their results (2026-10-15)

1. **All Phase 1–3 tests re-run under the new setting:** unit **150/150**, fork **119/119**.
2. **Every gate re-run:**
   - opcode check: ok (0 CALL/DELEGATECALL/CALLCODE, 5 STATICCALL);
   - seam check: ok;
   - coverage gate: ok (every `src/` file present, 100% lines and ≥95% branches per file);
   - sizes: guard 6,883 B, factory 8,669 B.
3. **Per-file coverage thresholds kept.**
4. **Solidity known-bugs check for 0.8.28.**
   - **Source:** `docs/bugs_by_version.json` and `docs/bugs.json` from `ethereum/solidity` (`develop`),
     downloaded 2026-10-15. 0.8.28 lists 7 bugs.
   - **Our configuration:** legacy pipeline (`via_ir = false`), optimizer on with default details,
     which means **the Yul optimizer is enabled** (verified in the build-info:
     `{"enabled": true, "runs": 200}`, no `details`), `evm_version = cancun`.

| Bug | Severity | Conditions | Applies to us? |
|---|---|---|---|
| `TransientStorageClearingHelperCollision` (fixed 0.8.34) | **high** | `viaIR`, cancun | **No:** `via_ir` is off. **Rule: never enable `via_ir` on 0.8.28.** The guard clears transient state and also uses storage, so the bug would be relevant under via-IR. |
| `UnsoundSpillInMutualRecursion` (fixed 0.8.36) | medium | `viaIR` | No |
| `SpillSlotCollisionAcrossMutualRecursion` (fixed 0.8.37) | low/medium | `viaIR` | No |
| `MisorderedNamedParametersInRequireWithCustomErrors` (fixed 0.8.37) | very low | `viaIR` | No |
| `MemoryByteArrayElementDeleteClearsWholeWord` (fixed 0.8.37) | low/medium | legacy pipeline | **Not triggered:** `src/` contains no `delete`. Rule: no `delete` on memory `bytes` elements. |
| `LostStorageArrayWriteOnSlotOverflow` (fixed 0.8.32) | low | none | **Not triggered:** `src/` has no storage arrays. Recheck whenever a storage array is added (Phases 6+). |
| `YulOptimizerKnowledgeBaseStaleBookkeeping` (fixed 0.8.38) | low | `yulOptimizer` | **⚠️ In scope.** The Yul optimizer is on under our settings. It runs on inline assembly and on solc's generated Yul utility code. The bug can replace a load with a stale value, or drop a needed store, when two addresses computed from a reassigned variable coincide at runtime. Our current assembly is a single `mload` (`MemoryReader`), but the Phase 7 transient token map (keccak-keyed `tstore`/`tload`) is exactly the kind of code to worry about. **Owner decision pending:** see the sub-decision. |

### Sub-decision: the Yul-optimizer bug (owner, 2026-10-15): option A

- **A. Keep the legacy optimizer on, turn the Yul optimizer off**
  (`[profile.default.optimizer_details] yul = false`). Measured: guard **7,461 B** (+578), factory
  **9,731 B** (+1,062). Both are still far under the caps. This removes the bug's precondition.
- **B. Upgrade solc to ≥ 0.8.38**, which fixes all 7 listed bugs. This needs a new known-bugs check
  for that version, a re-run of everything, and a check of the `transient` and other features we
  rely on.
- **C. Accept it** (low severity) and add targeted differential tests for the Phase 7 transient map.

**Decided: A.** `[profile.default.optimizer_details] yul = false`.

## The frozen toolchain

**solc 0.8.28, legacy pipeline (`via_ir` off), optimizer on with `runs = 200`, Yul optimizer off.**

- **Verified in the build-info:** `{"enabled": true, "runs": 200, "details": {"yul": false}}`,
  `viaIR` unset.
- **Re-run under it on the committed Phase 3 code:**
  - unit **150/150**, fork **119/119**;
  - opcode, seam and coverage gates ok, fmt clean;
  - sizes: `SafeFirewallGuard` **7,461 B** runtime (8,423 B init), `GuardFactory` **9,731 B**.
- **The compiler version is revisited once, deliberately, before the Phase 10 freeze**, with a fresh
  known-bugs check (0.8.38+ fixes every bug listed above). There are no ad-hoc changes before then.
- **Regardless of compiler settings,** the Phase 7 transient map is fuzzed against a plain reference
  implementation (a storage-backed mapping and array) for every operation.

### Test toolchain: forge pinned at v1.8.5 (owner, 2026-10-22)

**forge 1.8.5 locally and in CI, pinned exactly, never `stable` or `latest`.**

- **Why.** CI installed whatever forge was stable (`foundry-toolchain@v1` with no version), while
  local runs used 1.5.1. Forge 1.8.5 treats each top-level test call as its own transaction. It
  resets transient storage between those calls and charges intrinsic gas (about 21,000) for each.
  `test_PostHook_PathMismatchReverts` relied on transient state carrying over between two pranked
  calls, so it failed in CI only. It was rewritten to produce the mismatch inside one real
  execution (a module transaction that delegatecalls a forwarder into the signed post-hook, on
  `PostCheckOnlyGuard`). Transient storage is per transaction by definition, so no test may rely on
  how forge handles it between top-level calls.
- **Forge is the test tool; solc produces the bytecode.** Bytecode hashes (`forge inspect <C>
  bytecode|deployedBytecode | cast keccak`) were recorded before and after the upgrade, on the same
  commit (`e138bfd`). They are identical:

  | Contract | Init code (`bytecode`) | Runtime (`deployedBytecode`) |
  |---|---|---|
  | `SafeFirewallGuard` | `0xb2d3eea9c048446dad6791a9e9dfd63c96eaabb5482895674c1b63126b2b8264` | `0xc33f31eab444e03fcbb08d8161af2b84c42e58f73b137f4284f2f36141fa6056` |
  | `GuardFactory` | `0xb2f938e1bd997d776650a213ddce0efb5afc535081ac649e4c424a12a9b341d8` | `0x736b2531c99c15af510c550a3a57c62cc2b7aa140a40143274dc5eabe7067524` |

  Any future forge change repeats this check: the hashes must match, or the change is a compiler
  change and needs the known-bugs check above.
- **Every gate re-run on 1.8.5:** unit 219/219, fork 188/188, coverage 100% (completeness gate ok),
  fmt clean, opcode, seam and size gates ok, Slither 21 findings (all triaged).
- **Measured gas changed, the code didn't.** Each top-level test call now includes intrinsic gas,
  and fork tests run under the fork block's gas limit (about 57M, not 1B). So gas figures are
  comparable only within one forge version. The snapshot was regenerated on 1.8.5 as the new
  baseline.
- **The snapshot gate** (`script/gas-snapshot.sh`) covers unit-variant tests that are not fuzz
  tests. Fuzz means change with the inputs (even with a fixed seed they differed between sequential
  and parallel runs), and fork entries would need RPC in the unit job. With this scope the snapshot
  is deterministic and needs no secrets.
- **The 1.5.1 `expectRevert("")` panic is fixed in 1.8.5.** `vm.expectRevert(bytes(""))` against
  non-empty revert data now fails the test cleanly. Checked with a throwaway probe, which was then
  deleted. `_execTxExpectEmptyRevert` stays: it states the intent explicitly and doesn't depend on
  a forge version.
- **New in 1.8.5: lint warnings at build time** (`block-timestamp`, `require-revert-in-loop`,
  `reentrancy-events`, `encode-packed-collision`, `environment-read-across-mutation` in tests).
  They are warnings only. They're triaged when the code they point at is next touched.
- **CI pins every action to a commit SHA and pins the runner image (`ubuntu-24.04`)**, for the same
  reason (ADR 0013).

## Consequences

- The fork variant still runs the real mainnet Safe (built with 0.7.6, optimizer off). The unit
  variant's locally built Safe is now compiled with the optimizer on, which is another reason the
  fork variant stays mandatory (ADR 0013).
- Any change to the compiler version, the optimizer settings or `via_ir` requires this known-bugs
  check again, plus a full re-run of tests and gates.
- Any change to the forge version requires the bytecode-hash check above, plus a full re-run of
  tests and gates on both variants.
