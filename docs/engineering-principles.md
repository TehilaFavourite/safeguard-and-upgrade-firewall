# Engineering Principles

## Design principles

- **P1:** An action may be fast only if it reduces power (cancel, revoke, pause) **and** cannot
  reduce the signers' ability to reach the threshold. Anything else goes through the timelock
  (ADR 0016).
- **P2:** Deny by default. Unconfigured tokens have cap 0. Unlisted targets and operators are rejected.

## Sources of truth

`docs/v1-spec.md`, `docs/threat-model.md` and `docs/adr/` define the design. If an instruction
conflicts with them, stop and resolve it as a decision. Never resolve it silently in code. A gap
the spec doesn't cover goes into "Open v1 items" in `docs/v1-spec.md` and is decided before it is
implemented. Every design decision is recorded as an ADR (context, options, decision,
consequences).

The v1 scope is fixed by ADR 0009. Every new question goes into either the v1 list or the v2
backlog. No open-ended design rounds.

## Engineering standard

- **Compiler:** Solidity 0.8.28, EVM `cancun` (`foundry.toml`).
- **Transient state:** use typed `transient` variables. **Single exception:** the per-token
  transient map library (ADR 0005) is the only place in `src/` where inline assembly is allowed.
  It requires 100% line and branch coverage, and its slot derivation is documented and
  collision-tested.
- **Structure:**
  - one contract per responsibility, with pure logic in internal libraries;
  - no external "pluggable policy" calls: one audited artifact and no extra call surface.
- **Not upgradeable.** The guard is replaced only through the escape path (R1, ADR 0014).
- **Errors:** custom errors only, no revert strings. Each error carries the data needed to
  diagnose it.
- **Events:** one for every state change and every queue, execute, cancel or expiry, designed so
  the alert bot can work from events alone. Blocked transactions revert and cannot emit events;
  the bot decodes their revert data instead (v1 spec).
- **NatSpec:** on every external and public function, with `@dev` notes referencing the ADR that
  justifies the behaviour.
- **Constants:** no magic numbers; use named constants.
  - Storage slot constants (singleton, guard, module guard, fallback handler, module and owner
    sentinels) must come from the installed Safe v1.5.0 source, with `file:line` cited in a
    comment.
  - Canonical external addresses are constructor immutables, verified by `extcodehash` in the
    deploy script (ADR 0013).
- **Coding practice:** checks-effects-interactions, explicit visibility everywhere, immutables
  where possible.
- **Tooling gates:**
  - `forge fmt` clean;
  - Slither run on `src/`, with every finding fixed or triaged in `docs/slither-triage.md`;
  - coverage on `src/`: 100% lines and at least 95% branches, with every uncovered branch
    explained;
  - a `forge snapshot` committed, so gas changes are visible in review.

## Workflow per phase

1. **Invariants.** Write the phase's invariants in plain English, each traced to a spec line or
   ADR. The maintainer approves them.
2. **Tests.** Write the tests (unit tests, plus fuzz tests where inputs vary). The maintainer
   reviews every assertion.
3. **Implementation.** Implement until all tests pass on both Safe sources: the local build, and
   the fork singleton when `ETH_RPC_URL` is set (ADR 0013).
4. **Checks.** Run `forge fmt --check`, `forge build`, `forge test -j 1` (single-threaded, because
   the fork variant hits RPC rate limits in parallel; ADR 0013), `forge coverage` and Slither.
   Report the results as they are, including failures.
5. **Summary.** A five-line summary, any decisions that came up, and the proposed commits.

The phase list is in `docs/build-plan.md`.

## Commits

- Conventional Commits style.
- The maintainer makes every commit, after reviewing the diff.
- Commit messages carry no co-author or "generated with" trailers.
