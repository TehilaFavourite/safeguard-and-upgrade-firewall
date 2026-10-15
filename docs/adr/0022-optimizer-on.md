# ADR 0022: Compile with the optimizer on (200 runs)

- Status: Accepted (one sub-decision open: the Yul-optimizer bug, see below)
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

### Open sub-decision: the Yul-optimizer bug

- **A. Keep the legacy optimizer on, turn the Yul optimizer off**
  (`[profile.default.optimizer_details] yul = false`). Measured: guard **7,461 B** (+578), factory
  **9,731 B** (+1,062). Both are still far under the caps. This removes the bug's precondition.
- **B. Upgrade solc to ≥ 0.8.38**, which fixes all 7 listed bugs. This needs a new known-bugs check
  for that version, a re-run of everything, and a check of the `transient` and other features we
  rely on.
- **C. Accept it** (low severity) and add targeted differential tests for the Phase 7 transient map.

## Consequences

- The fork variant still runs the real mainnet Safe (built with 0.7.6, optimizer off). The unit
  variant's locally built Safe is now compiled with the optimizer on, which is another reason the
  fork variant stays mandatory (ADR 0013).
- Any change to the compiler version, the optimizer settings or `via_ir` requires this known-bugs
  check again, plus a full re-run of tests and gates.
