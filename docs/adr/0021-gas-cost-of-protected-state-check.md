# ADR 0021: Accept the gas cost of the protected-state check

- Status: Accepted
- Date: 2026-10-14

## Context

Phase 2 adds the expected-singleton check, the protected-state snapshot and the post-check
comparison (ADR 0020). These read the Safe on every guarded execution, including the full owner list
and module list twice.

## Measurements (Phase 2; 3 owners, 1 module)

**Whole transaction**, from `forge snapshot --diff` against the Phase 1 snapshot:

| Transaction | Phase 1 | Phase 2 | Increase |
|---|---|---|---|
| Signed ETH transfer (`test_Skeleton_AllowsOrdinaryCall`) | 115,463 | 186,286 | **+70,823** |
| Module transaction (`test_Path_ModulePathRecorded`, includes a probe call) | 66,025 | 140,359 | **+74,334** |

**Per hook**, from `forge test -vvvv` traces of the signed transfer:

| | Unit (local Safe) | Fork (mainnet 0.7.6 singleton) |
|---|---|---|
| `checkTransaction` | 46,969 | 43,305 |
| `checkAfterExecution` | 29,094 | 25,430 |

**Breakdown of the unit-variant pre-check / post-check:**

| Read | Pre-check | Post-check |
|---|---|---|
| `getOwners()` (3 owners) | 9,623 | 3,623 |
| `getModulesPaginated()` (1 module) | 6,896 | 2,896 |
| `getStorageAt` × 3 | 8,422 | 4,422 |
| `getThreshold()` | 521 | 521 |

- The owner and module reads are about 23k of the roughly 76k total (about 30%). They grow with list
  length.
- The rest is `masterCopy()` (×2), the expected-singleton SLOAD, transient writes, hashing, and the
  call overhead into the proxy.

## Cost in USD

Prices read from mainnet at block 26,193,446 (2026-10-14 21:31 UTC):
- base fee **0.150 gwei** (`cast block … --field baseFeePerGas`);
- ETH/USD **$2,418.23**, from the Chainlink feed `0x5f4e…8419` (`description()` = "ETH / USD",
  8 decimals).

| Gas price | Signed tx (+70,823) | Module tx (+74,334) |
|---|---|---|
| 0.15 gwei (at measurement) | $0.026 | $0.027 |
| 1 gwei | $0.17 | $0.18 |
| 10 gwei | $1.71 | $1.80 |
| 50 gwei (congestion) | $8.56 | $8.99 |

The USD figures scale linearly with the ETH price. For example, a treasury making 1,000 guarded
transactions a year at 10 gwei pays about $1,700 a year extra.

## Options

### A. Accept the cost now; revisit with real numbers after Phase 10
### B. Optimize now
For example, reading list lengths instead of hashing whole lists, or caching. This means less
coverage of the protected state, or more code, for a cost that is small relative to the assets.

## Decision

**Option A** (owner, 2026-10-14). No optimization now.

Owner's reasoning: for a treasury Safe, defence in depth beats gas. A few dollars per transaction is
negligible next to the value the check protects (the Bybit Safe held ~401k ETH,
`docs/bybit-incident.md`).

## Consequences

- Revisit after Phase 10 (the stateful invariant suite), with numbers for the full pipeline. Any
  optimization must keep every Phase 2 test green.
- The per-transaction cost grows with the number of owners and modules. `MAX_MODULES = 16`
  bounds the module side (ADR 0020).
