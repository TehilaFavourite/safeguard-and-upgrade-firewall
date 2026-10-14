# ADR 0009: v1 scope

- Status: Accepted
- Date: 2026-10-09

## Context

Each design round opened new questions. Without a fixed scope, the project doesn't reach tests or
code.

## Options

### A. Fix a narrow v1, and file every new question into v1 or the v2 backlog
### B. Keep designing until every question is resolved

## Decision

**Option A.**

**v1 includes:**
- Ethereum mainnet only
- ERC-20 and ETH
- one guard per Safe
- the alert bot
- the Bybit fork demo

**Out of scope for v1:**
- NFTs (ERC-721 and ERC-1155)
- a restrictive fallback handler
- L2s
- a shared guard
- oracle-based caps

Every new open question goes into either v1 or the v2 backlog (`docs/v1-spec.md`). No open-ended
design rounds.

## Consequences

- Transient storage (ADR 0005) is safe to use, because mainnet is post-Cancun.
- Out-of-scope items are documented limitations in the threat model, not silent gaps.
- With NFTs out of scope, no `setApprovalForAll` operator is allowlisted in v1, so every
  `setApprovalForAll(op, true)` is rejected.
