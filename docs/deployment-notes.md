# Deployment Notes

## Install order (required)

The guard blocks delegatecall except to allowlisted targets. `SafeMigration` only runs via
delegatecall (`lib/safe-smart-account/contracts/libraries/SafeMigration.sol:45-46`, `onlyDelegateCall`).
Migrating after the guard is installed would therefore be blocked, so the order is:

0. **Deploy the guard.** Before deploying, the deploy script verifies the `extcodehash` of every
   canonical address passed to the constructor (`MultiSendCallOnly`, `Permit2`, …) against its
   recorded mainnet value (ADR 0013).
1. **Migrate the singleton to v1.5.0, as a separate transaction before the install batch.**
   Delegatecall `SafeMigration.migrateSingleton()` (or `migrateWithFallbackHandler()`) from the
   Safe. It cannot be part of the batch: `SafeMigration` requires delegatecall
   (`SafeMigration.sol:45-46`), and `MultiSendCallOnly` reverts on inner delegatecalls
   (`MultiSendCallOnly.sol:57-58`).
2. **Install as one atomic batch** (a single Safe transaction delegatecalling `MultiSendCallOnly`):
   0. CALL `GuardFactory.deploy(config)`. The factory is permissionless and idempotent: if anyone
      has already deployed this exact guard, the call returns the existing address, so the batch
      does not revert. The guard lands at the address predicted from (safe, version, constructor
      args), which the later steps use (ADR 0007).
   1. CALL a checker contract that reads the Safe's module list and reverts unless it matches an
      expected hash. The check runs at execution time, not proposal time, so it cannot go stale.
   2. Revoke every (token, spender) pair on the reviewed allowance list (`approve(spender, 0)`),
      explicitly including Permit2 on every held token (ADR 0004, item 6).
   3. `setGuard(guard)`
   4. `setModuleGuard(guard)`

   Order within the batch doesn't affect enforcement. The install transaction cached
   `guard == address(0)` at `Safe.sol:149`, so no guard hook runs on any step.

   If any step reverts, the whole batch reverts. The Safe is never left half-installed.

   Open points for the checker (decide before implementing):
   - Read the full list via `getModulesPaginated(SENTINEL, n)`. Require `next == SENTINEL` so a
     longer list can't hide behind a page limit.
   - Fix the hashing convention, including order. The linked list returns modules newest-first.
   - Optionally also assert that the singleton, guard and module guard slots hold their expected
     pre-install values.

## Pre-install allowance scan

An off-chain script scans the Safe's historical `Approval` events (owner = Safe) into a
(token, spender) list. The owner reviews the list, and it feeds step 2 of the install batch.
Tokens that don't emit `Approval` are not found. This is a trust assumption (threat model §6).

**Revocation dry run (ADR 0004, item 7):** the script dry-runs every `approve(spender, 0)` on a
fork before the batch is built. Tokens that revert are revoked with `approve(spender, 1)` instead.

### Tokens revoked with `approve(spender, 1)`

| Token | Address | Verified on fork (block) |
|---|---|---|
| BNB | `0xB8c77482e45F1F44dE1745F52C74426C631bDD52` | 26,191,613: `approve(_, 0)` reverts, `approve(_, 1)` returns `true` (eth_call). Identity checked by `name()`/`symbol()` = "BNB" and 18 decimals; cross-check against Etherscan |
| *(further tokens filled in by the scan)* | | |

## Notes

- The install transaction gets no post-check from our guard. `execTransaction` caches
  `guard == address(0)` at `Safe.sol:149` before the `setGuard` call executes (see ADR 0001).
- Later singleton upgrades go through the timelocked singleton-migration item (ADR 0015), with no
  guard removal. That ADR is still Proposed.
