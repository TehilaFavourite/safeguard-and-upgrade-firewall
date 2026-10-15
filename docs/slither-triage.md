# Slither Triage

Command: `slither . --filter-paths 'lib/|test/|script/' --exclude-dependencies`.

Every finding is either fixed or triaged here, with a reason.

## Phase 2 (2026-10-14, Slither 0.11.6)

24 contracts analyzed with 102 detectors: **10 results, all informational or optimization**. No
high, medium or low findings.

| # | Detector | Location | Status | Reason |
|---|---|---|---|---|
| 1 | `dead-code` | `SafeFirewallGuard._activePath()` | Accepted | Test seam for invariant I1.8, used only by `test/harness/SafeFirewallGuardHarness.sol`. It is `internal` with no external entry point, so it adds no attack surface. The alternative, a production view of the transient path, was rejected in Phase 1. |
| 2-4 | `naming-convention` | `SafeFirewallGuard.SAFE`, `MULTISEND_CALL_ONLY`, `PERMIT2` | Accepted | Immutables use UPPER_CASE by Solidity style-guide convention. |
| 5-8 | `naming-convention` | `ISafeFirewallGuard.SAFE()`, `MULTISEND_CALL_ONLY()`, `PERMIT2()`, `IGuardFactory.VERSION()` | Accepted | Getters for the immutables and constant above, named to match. |
| 9 | `too-many-digits` | `GuardFactory._predict` | False positive | The flagged "literal" is `type(SafeFirewallGuard).creationCode`, not a numeric literal. |
| 10 | `immutable-states` | `SafeFirewallGuard._expectedSingleton` | Accepted, revisit in Phase 8 | Deliberately storage: the timelocked singleton-migration item (ADR 0015, Phase 8) updates it. Making it immutable now would change the storage layout when Phase 8 lands. If Phase 8 replaces the guard on migration instead, this becomes an immutable. |

## Phase 3 (2026-10-15, Slither 0.11.6)

26 contracts analyzed with 102 detectors: **11 results**. The 10 from Phase 2 are unchanged
(#1-10 above, same reasons). There are two Phase 3 findings: one fixed, one triaged.

| # | Detector | Location | Status | Reason |
|---|---|---|---|---|
| 11 | `uninitialized-local` | `MultiSendDecoder.decode`: `count` | **Fixed** | Solidity zero-initializes locals, so this wasn't a bug. `count` and `pos` are now initialized explicitly for clarity. |
| 12 | `assembly` | `MemoryReader._load` | Accepted | The approved second assembly exception (ADR 0005; engineering principles). Read-only: one `mload` after an overflow-safe bounds check, no `mstore`, marked `memory-safe`, 100% covered and fuzzed against a byte-by-byte reference. |

## Phase 4 (2026-10-15, Slither 0.11.6)

26 contracts analyzed with 102 detectors: **21 results**, all informational. No high, medium or
low findings. The 11 from Phase 3 are unchanged (#1-10 and #12 above, same reasons). There are 10
Phase 4 findings, all triaged.

| # | Detector | Location | Status | Reason |
|---|---|---|---|---|
| 13-16 | `timestamp` | `queueEscape`, `markExpired`, `_requireExecutable`, `_isLive` | Accepted | The timelock is defined in wall-clock time (ADR 0011). The delays are 48h, 72h and 14 days. A proposer can shift `block.timestamp` by seconds at most, which is negligible at that scale. The boundaries (`eta`, `expiresAt`) are tested at ±1 s. |
| 17 | `dead-code` | `SafeFirewallGuard._advanceKeyEpoch` | Accepted | The Phase 7 and 8 power-reducing changes call it (ADR 0023, D6). Until then only the test harness reaches it. It is `internal`, so it has no external entry point. |
| 18 | `low-level-calls` | `SafeFirewallGuard._staticWord` | Accepted | The I4.20 binding reads (ADR 0023): `staticcall` only, with success, length and decode checked explicitly, and every failure reported as `EscapeTargetNotBound`. A high-level call would revert with the target's own data and couldn't be checked against length. `check-guard-opcodes.sh` confirms there are 0 CALL, DELEGATECALL or CALLCODE. |
| 19-22 | `naming-convention` | `ISafeFirewallGuard.ESCAPE_DELAY()`, `CONFIG_DELAY()`, `GUARDIAN_DELAY()`, `EXPIRY_WINDOW()` | Accepted | Getters for the constants, named to match (as #5-8). |
