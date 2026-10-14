# v1 Spec: Safe Upgrade Firewall

**Target:** Safe v1.5.0, Ethereum mainnet, ETH and ERC-20. One guard per Safe, deployed by a factory,
with the Safe address immutable (ADR 0001, 0007, 0009).

**Principles:** P1 means an action is fast only if it reduces power and cannot reduce the signers'
ability to reach the threshold; everything else is timelocked (ADR 0016). P2 means deny by
default.

## Hooks (both paths, same pipeline)
| Rule | Where |
|---|---|
| Revert unless `msg.sender == safe` | all four hooks |
| Transient reentrancy flag: checked on entry, set in the pre-check, cleared in the post-check. Records which path is active (signed or module). | all four hooks (ADR 0005, 0007) |
| Refund fields zero, **before** R1 and R2 | signed pre-check (ADR 0010, 0014) |
| Escape path: exactly one top-level call (ADR 0014). Fast return before any policy runs on the signed path; **rejected** on the module path. | both pre- and post-check (R1) |
| Cancellation (Call to the Safe itself, value 0, empty data, no refund fields) always passes | pre-check (R2) |
| Config calls on the module path are rejected | module pre-check (ADR 0014) |

**Pre-hook order** (ADR 0014):
1. caller check;
2. reentrancy;
3. path flag;
4. refund fields zero;
5. R1 escape;
6. R2 cancellation;
7. reject other calls to `GUARD` (ADR 0018);
8. slot snapshot;
9. policy pipeline.

**Post-hook order:**
1. R1 fast return (driven by a transient marker);
2. compare slots against the snapshot;
3. if `success`, settle and debit the token buckets;
4. clear transient state.

**Transient state:** value types use typed `transient` variables. Per-token totals use the single
assembly library (keyed map plus bounded list, at most 8 tokens per transaction, `TooManyTokens`
above that) (ADR 0005).

## Pre-check policy pipeline (every call, including each inner batch call)
1. **Refunds:** `gasPrice == 0`, `gasToken == 0`, `refundReceiver == 0` (ADR 0010). This runs in
   the hook prefix, before R1 (ADR 0014), and applies to every signed transaction.
2. **Delegatecall:** only the pinned v1.5.0 `MultiSendCallOnly`. Plain `MultiSend` is rejected.
   Modules may never delegatecall.
3. **Batch decoding:** canonical ABI wrapper, strict tiling, every `dataLength` in bounds, no
   trailing bytes, operation byte must be `0`. Normalize `to = 0` to the Safe. Empty batches are
   rejected (ADR 0003).
4. **Self-calls** (ADR 0016):
   - `disableModule` is immediate;
   - `enableModule`, `setFallbackHandler`, `changeThreshold`, `addOwnerWithThreshold`,
     `removeOwner` and `swapOwner` are allowed only as matured timelock items;
   - `setGuard` and `setModuleGuard` are allowed only through the escape path (ADR 0014):
     `setModuleGuard(x)` first, and `setGuard(x)` only once the module guard slot equals `x`.
5. **Allowlist** (ADR 0017, 0018):
   - selector entries are (target, selector, allowValue), deny by default, and apply only when
     calldata is at least 4 bytes;
   - empty-calldata value transfers use `valueRecipient[target]`;
   - calldata of 1–3 bytes is rejected;
   - `value > 0` requires `allowValue`;
   - entries constrain free parameters such as the recipient;
   - **`to == GUARD`** is rejected unless the selector is a guard config or escape function. Hook
     selectors are always rejected, and `GUARD` is never an allowlisted target (ADR 0018).
6. **Upgrade-class calls** (upgrades, beacon upgrades, admin transfers, role grants) are allowed
   only as matured items. The item binds the implementation address, its `extcodehash` and the
   hash of the initializer calldata, all re-checked. Delay ≥ the proxy's withdrawal period
   (ADR 0006).
7. **Outflow caps:** per token, no oracle. Token bucket: capacity = cap, refilling linearly at
   cap per 24h (ADR 0012). Unconfigured tokens have cap 0. ETH
   `value` counts. Approvals count in full at approval time. Unlimited approvals are rejected.
   Spenders must be allowlisted, except that `approve(_, 0)` and `approve(_, 1)` skip the spender
   allowlist (1 still counts against the bucket). Permit2 is never allowlisted: `approve(Permit2, 0)`
   passes, and any non-zero approval to Permit2 is rejected. `setApprovalForAll(op, true)` is a
   hard reject. Exact-match revocations pass and
   are not counted. The running total accumulates across a batch (ADR 0004).

## Post-check
- Invariants unchanged unless a matured item authorized the change: singleton, guard, module guard,
  fallback handler, module list, owners, threshold.
- **Read order (ADR 0020):** the singleton is read via the proxy's `masterCopy()` and compared
  first. The other fields are read through the Safe's getters only after that.
- **Module list:** at most `MAX_MODULES = 16`; above that, `TooManyModules`.
- **R2 cancellation:** skips the comparison.
- **Outflow:** if `success == true`, check the per-token totals (passed from the pre-check through
  transient storage) against the bucket level, then debit. Revert if a total exceeds the level
  (ADR 0005, 0012).
- **Bound:** at most cap per transaction (a batch counts as one), and at most 2× cap in any 24h
  period.

## Config and timelock
- Config changes are queued, then executed after the delay. Cancellation is possible. Enforced
  inside the guard's own functions (ADR 0002).
- Queuing and executing require the signed path. Modules cannot do either.
- **Cancel rights (ADR 0008).**
  - The guardian can cancel anything except escape-path items and guardian removal or replacement.
  - Signers (signed path) can cancel everything; signer-cancel sits in the R1 minimal path.
- **The alert bot** has two sources:
  - guard events (`Queued` with countdown, executions, cancellations, expiry, guardian actions,
    cap near-exhaustion);
  - failed transactions to the Safe. Each one is re-run with `eth_call` at the parent block to get
    the revert data, which is decoded against the guard's custom errors. A blocked transaction
    reverts, so it cannot emit an event (open item 7, resolved).
- **Delays (ADR 0011), immutable in v1:**

  | Item class | Delay |
  |---|---|
  | Config | 48h |
  | Escape path | 72h, which is the worst-case freeze |
  | Proxy upgrade | `max(7d, withdrawal period + 24h)` |
  | Guardian change | 48h |

- **Expiry:** queued items expire 14 days after their ETA.
- **Proxy withdrawal period:** raising it is a 48h config change. Lowering it takes effect only
  after the proxy's current upgrade delay (ADR 0011).
- **Cap changes:** settle the bucket at the old rate first. Raising keeps the level and is
  timelocked (48h). Lowering clamps the level and is immediate through the signed path (ADR 0012).
- **Opposite pending changes:** a power-reducing change to a key (a token's cap, a proxy's
  withdrawal period) cancels every pending power-adding change to that same key (ADR 0011, 0012).

- **Singleton migration** (ADR 0015): one top-level `DelegateCall`, timelocked at the escape-class
  delay (72h).
  - Bound per item: the migration contract address and its `extcodehash`, the calldata hash
    (only `migrateSingleton()`), and the resulting singleton address and its `extcodehash`.
  - The post-check accepts a slot 0 change only to that singleton, and only while both guard slots
    point at this guard.
- **Timelocked self-calls** (owners, threshold, `enableModule`, fallback handler) use the 72h
  escape class (ADR 0016).
- **Canonical addresses** (`MultiSendCallOnly`, `Permit2`) are constructor immutables. The deploy
  script verifies their `extcodehash` against mainnet (ADR 0013).

## Install (one atomic `MultiSendCallOnly` batch; migration is a separate transaction before it)
0. `GuardFactory.deploy(config)`, as a CALL from the Safe. The factory is permissionless and
   idempotent: an existing deployment at the predicted address is returned, not re-deployed. All
   config is in constructor arguments, and the address is predicted from
   (safe, version, constructor args) (ADR 0007).
1. Checker contract: the module list must match the expected hash (full list, `next == SENTINEL`).
2. Revoke every pair on the reviewed (token, spender) list from the `Approval` event scan,
   including Permit2 on every held token. Revocations are dry-run on a fork first; tokens that
   revert on `approve(_, 0)` get `approve(_, 1)` (ADR 0004).
3. `setGuard(guard)`
4. `setModuleGuard(guard)`

## Testing (ADR 0013)
One suite, two Safe sources. An abstract base with a `_deploySafe()` hook has two variants:
- **unit:** local 0.8.28 build;
- **fork:** the real mainnet v1.5.0 singleton at a pinned block.

Every feature test runs against both.

## Deliverables
Guard + factory, install checker, alert bot, Bybit fork demo, runbook.

---

## Open v1 items (decide before writing tests)

None open.

Resolved 2026-10-14 (fifth round, on-chain verification):
- Bybit's Safe was v1.1.1 (3 of 6, nonce 71) at the pre-hack block 21,895,237; slot 0 changed in
  block 21,895,238 (ADR 0013);
- BNB reverts on `approve(_, 0)` (deployment notes);
- two pinned fork blocks; the Phase 11 demo deploys v1.5.0 itself (ADR 0013).

Resolved 2026-10-14 (fourth round):
- the factory is permissionless and idempotent, and escape items bind the new guard's address and
  `extcodehash` (ADR 0007, 0014);
- Permit2 is excluded from the `approve(_, 1)` exception (ADR 0004).

Resolved 2026-10-14 (third round):
- factory and constructor-only config (ADR 0007);
- calls to the guard (ADR 0018);
- 72h class for timelocked self-calls (ADR 0016);
- `valueRecipient` mapping replacing the `bytes4(0)` sentinel (ADR 0017);
- `approve(_, 0/1)` skipping the spender allowlist (ADR 0004).

Resolved 2026-10-14 (second round):
- migration binding per item (ADR 0015, accepted);
- enforced replacement order (ADR 0014);
- self-call classification and the refined P1 (ADR 0016);
- empty batches rejected (ADR 0003);
- allowlist entry shape (ADR 0017);
- revocation fallback for tokens that revert on zero (ADR 0004).

Resolved 2026-10-14 (first round):
- hook order and refund check before R1, module-path rejection, escape transaction shape
  (ADR 0014);
- transient per-token map (ADR 0005);
- bot sources;
- `setApprovalForAll` hard reject (ADR 0004);
- migration as a separate transaction;
- ADR 0002 amendment;
- canonical addresses as immutables (ADR 0013).

Resolved earlier: ADRs 0004, 0008, 0011, 0012, 0013.

## v2 backlog
NFTs and `setApprovalForAll` operators, a restrictive fallback handler (EIP-1271), L2s, a shared
guard, oracle-based caps, relayer refunds, bot simulation of pending Safe Transaction Service
transactions.
