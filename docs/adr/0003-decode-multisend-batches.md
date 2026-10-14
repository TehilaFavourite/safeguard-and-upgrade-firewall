# ADR 0003: Decode MultiSendCallOnly batches in the pre-check

- Status: Accepted
- Date: 2026-10-09

## Context

`MultiSendCallOnly` is an allowlisted delegatecall target. When the Safe delegatecalls it,
`checkTransaction` sees only the outer transaction (`to = MultiSendCallOnly`,
`operation = DelegateCall`, `data = multiSend(bytes)`). The inner calls then run in the Safe's
context with `msg.sender == safe` (`contracts/libraries/MultiSendCallOnly.sol:54`), so they skip
every pre-check policy: target/selector allowlist, outflow caps and self-call timelock.

The post-execution check catches changes to Safe storage slots, but not outflows or allowlist
violations.

## Options

### A. Decode the batch in the pre-check and run each inner call through the policy pipeline
- (+) One policy, applied identically to single transactions and batches.
- (−) The guard needs its own parser, and any difference from `MultiSendCallOnly`'s parsing is a
  bypass (see Consequences).

### B. Ban batching (no delegatecall allowlist at all)
- (+) No parser.
- (−) Breaks the normal Safe{Wallet} batching UX, including the atomic install batch.

### C. Allow batching, rely on the post-check only
- (−) Outflow and allowlist rules are bypassable by wrapping any call in a batch.

## Decision

**Option A.** Decode `MultiSendCallOnly` batches in the pre-check and run every inner call through
the same policy pipeline as a top-level call. Specifically (owner, 2026-10-09):

- Before any policy runs, an inner `to == address(0)` is normalized to the Safe's address.
- The parser rejects anything that is not exactly well-formed: every `dataLength` must fit the
  buffer, and there may be no trailing bytes.
- The delegatecall allowlist pins only the v1.5.0 `MultiSendCallOnly` address. A test proves that
  plain `MultiSend` is rejected.
- **Empty batches are rejected** (P2; owner, 2026-10-14).

## Consequences: why this is harder than it looks

The guard's parser must accept **only** batches that it and `MultiSendCallOnly` interpret
identically. References are to `contracts/libraries/MultiSendCallOnly.sol`.

1. **`to == address(0)` means the Safe itself** (line 44:
   `to := or(to, mul(iszero(to), address()))`). Under delegatecall, `address()` is the Safe, so
   an inner entry with `to = 0` is a self-call such as `setGuard` or `enableModule`. The guard
   must normalize `0 → safe` before applying policy, or self-call rules are bypassed.

2. **Loose loop bound and no bounds checks.**
   - Line 33 loops `while i < length`, with `i` starting at `0x20` (it counts the length word).
     Trailing bytes are therefore handled inconsistently: up to 32 extra bytes are silently
     ignored, and more than 32 are parsed as another entry.
   - `dataLength` (line 48) is never checked against the buffer, so an entry can read memory past
     the end of `transactions`.

   The guard must parse **strictly** (entries tile the buffer exactly, no trailing bytes, every
   `dataLength` in bounds) and reject everything else. A strict guard is safe even though
   `MultiSendCallOnly` is lenient, because on exactly-tiled input both read the same entries.

3. **Operation byte.** Only `0` executes (line 53). `1` reverts (line 58), and 2-255 fall through
   with `success = 0` and revert (line 60). The guard should reject any operation byte other
   than `0` outright.

4. **The outer ABI layer.** `multiSend(bytes memory)` is decoded by Solidity's ABI decoder, which
   follows the encoded offset. The contract is compiled with solc 0.7.6, while our guard will
   use 0.8.x (ABI coder v2). The guard must:
   - check the selector;
   - decode with `abi.decode` rather than assuming the bytes start at a fixed offset;
   - for safety, require canonical encoding (offset `0x20`, length consistent with
     `data.length`).

5. **Allowlist by exact address, ideally by codehash.** Allow only the v1.5.0 `MultiSendCallOnly`
   (`0xA83c336B20401Af773B6219BA5027174338D1836`, per `CHANGELOG.md`). The plain `MultiSend`
   (`0x2185…7eB7`) executes inner delegatecalls (operation 1), which re-opens arbitrary delegatecall.

6. **Batch-level state.** Rolling outflow caps must accumulate across the inner calls of one batch
   (ten transfers each under the cap must not add up to more than the cap). The pipeline needs a
   running total across a batch, not just a per-call check.

7. **Approvals are deferred outflows.** This applies to all transactions, not only batches. An
   `approve(attacker, max)` moves no funds at execution time. The spender later calls
   `transferFrom` from their own account, and no guard sees it. Outflow policy must treat
   `approve`, `increaseAllowance`, `setApprovalForAll`, Permit2 approvals and similar as outflows,
   or block them. (Open decision.)

8. **Same pipeline on the module path.** `checkModuleTransaction` receives the same
   `(to, value, data, operation)` and must run the same decoder and policies.

9. **Gas.** Decoding scales with batch size and runs inside `execTransaction`. This is not a
   third-party DoS vector, but it raises execution cost for large batches.
