# ADR 0024: How timelocked Safe self-calls are queued, executed and checked

- Status: Accepted
- Date: 2026-10-22
- Builds on: ADR 0016 (classification and the 72h class), ADR 0014 (escape path), ADR 0018 (calls
  to the guard), ADR 0020 (protected-state check), ADR 0023 (queue mechanics)
- Amends: ADR 0018 (permitted guard selectors), ADR 0020 D1 (seam signature)

## Context

ADR 0016 says which Safe self-calls are immediate, timelocked or escape-only. It doesn't say how a
matured item reaches the Safe, how the post-check accepts the change, or what happens to every
other self-call. Phase 5 needs all of that fixed before tests are written. The guard can't execute
the call itself: it may not contain CALL (`script/check-guard-opcodes.sh`), and ADR 0023 D2 says
non-escape items run only as the Safe's own signed transaction.

## Options and decisions (owner, 2026-10-22)

### 5.1 Execution shape

Options: the signers sign the exact self-call and the guard matches it (A), or the guard executes
the item (B, which needs CALL and an ADR to allow it).

**Decision: A.**
- The signers sign the exact self-call as a normal Safe transaction to `SAFE`. The pre-check finds
  the item by `keccak256(data)`.
- **One pending item per exact calldata.**
- **Top-level only,** never inside a batch (as ADR 0023 D3).
- **Consumed in the post-hook, only on success** (as ADR 0023 D7).
- **Stale `prev` pointers are accepted.** `removeOwner`, `swapOwner` and `disableModule` take a
  positional `prev` (`OwnerManager.sol:73,90`; `ModuleManager.sol:142`). If the list changes during
  the 72h wait, the item fails at execution (GS205 / GS103) and stays unused. With `safeTxGas > 0`
  it stays QUEUED; with `safeTxGas == 0` the whole transaction reverts. The signers then queue a
  fresh item. The runbook says to avoid owner or module list changes while a list-changing item is
  pending.
- **Queue function:** `queueSelfCall(bytes data)`, signed path only. It is added to the closed
  ADR 0018 list of permitted guard selectors. Items are cancellable by the signers (`cancel`) and by
  the guardian (`guardianCancel`, ADR 0016), and they use the 72h class (ADR 0016).

**I5.16: canonical encoding at queue time.** `queueSelfCall(data)` reverts unless:
- the selector is one of the seven timelocked functions in ADR 0016's table;
- `data` has exactly the ABI length for that selector;
- every address word has clean high bits.

Reason: the mainnet Safe v1.5.0 (solc 0.7.6, ABI coder v1) truncates dirty address arguments
(ADR 0013, headline example). A dirty item would show reviewers one value during the 72h window and
execute with another.

### 5.2 Post-check for an authorized self-call

Options: (a) a field mask, where only the fields the function can change may change and the rest
are compared; (b) exact after-values computed in the pre-check.

**Decision: split by whether a human reviewed it.**
- **Timelocked items use (a), the field mask.** The calldata is bound, humans had 72h to review
  it, and step 8 has verified the singleton, so the Safe function that runs is the reviewed one.
- **`disableModule` uses (b), exact after-values.** It is immediate, so nobody reviewed it. The
  post-check requires the module list to equal the pre-check list minus exactly that module
  (ADR 0016 consequence).
- **Owner's rationale:** reviewed changes get a mask; unreviewed changes get exact verification.

Masks, from the Safe source:

| Function | May change | Source |
|---|---|---|
| `enableModule` | MODULES | `ModuleManager.sol:129-137` |
| `setFallbackHandler` | FALLBACK_HANDLER | `FallbackManager.sol:46-49` |
| `changeThreshold` | THRESHOLD | `OwnerManager.sol:108-114` |
| `addOwnerWithThreshold` | OWNERS, THRESHOLD | `OwnerManager.sol:57-67` |
| `removeOwner` | OWNERS, THRESHOLD | `OwnerManager.sol:73-85` |
| `swapOwner` | OWNERS | `OwnerManager.sol:90-103` |

### 5.3 Every other self-call

**Decision: rejected,** with `SelfCallNotAllowed(selector)`. That covers:
- `setup`, `simulateAndRevert`, `approveHash`, `execTransaction`;
- views, and selectors routed to the fallback handler;
- calldata of 1-3 bytes;
- **any `value > 0` to `SAFE`.**

The empty-calldata, value-0 call to `SAFE` stays R2 (cancellation). **`SAFE` can never be a Phase 6
allowlist target.**

### 5.4 `disableModule`

**Decision:**
- **Signed path:** immediate, top-level only, one per transaction.
- **Module path: rejected.** This is a documented exception to module-path parity (I5.11).
  Disabling a module reduces power, but a malicious module could use it to remove a recovery module
  instantly.
- **Accepted on the signed path:** the signers approve it, and it's the fast response to a
  malicious module. Disabling a recovery module reduces recovery options, which the threat model
  records.

### 5.5 `MAX_MODULES` for `enableModule`

**Decision:** `count + 1 <= MAX_MODULES` (16), checked at queue **and** at execute. Pending items
are not counted. A second item that would exceed the limit fails closed at execute, and
`disableModule` stays available.

### 5.6 Where the self-call rule sits

**Decision:** widen the seam `_checkOperation(to, operation, path)` into
`_checkCall(to, value, data, operation, path)`. It covers the delegatecall rule and the self-call
rule, and it runs for top-level calls and for each batch entry. `PostCheckOnlyGuard` overrides it,
so post-check tests still isolate the post-check. `script/check-seam-overrides.sh` is updated to
the new name.

## Consequences

- The R1 escape path (ADR 0014) is unchanged. `setGuard`/`setModuleGuard` with no matching pending
  escape are rejected at the pre-check (I5.8), not only at the post-check.
- Several Phase 2-4 tests that used a self-call to provoke the post-check now fail at the
  pre-check. Each one either flips its expectation or moves to `PostCheckOnlyGuard`. The Phase 5
  red-check lists them.
- The interim test `test_Delegatecall_InterimBatchInnerCallCaughtOnlyByPostCheck` flips to a
  pre-check rejection (I5.7).
- The v1 spec's pipeline step 4, post-check and config sections are updated (`docs/v1-spec.md`).
