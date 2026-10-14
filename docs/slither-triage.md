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
