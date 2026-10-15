# Findings

Things found while building the firewall that are not obvious from the Safe documentation. Each
entry gives the evidence, the test that pins it, and what it changed. The README links here.

## 1. The deployed Safe v1.5.0 accepts dirty address arguments (Phase 4)

**Finding.** The canonical v1.5.0 singleton on mainnet was compiled with solc 0.7.6 and ABI coder v1
(`lib/safe-smart-account/hardhat.config.ts:53`; `Safe.sol` has no `pragma abicoder v2`). ABI coder
v1 does not validate address arguments. `setModuleGuard(x)` with non-zero high 96 bits in the
argument word **succeeds** and stores the low 160 bits. The same sources compiled with solc 0.8.28
(ABI coder v2) revert on that input.

**Why it matters.** The firewall recognises escape steps by their calldata (ADR 0014). If R1 had
decoded the argument by truncation, signers could be shown one encoding of a transaction while a
different, never-reviewed encoding was accepted as the escape. R1 now requires a clean ABI word.
A dirty one is not an escape, so it takes the normal pipeline, and the post-check rejects the
guard-slot change.

**How it was found.** Mutation testing. Removing the clean-bits check survived every unit-variant
test and failed only on the fork variant, which runs the real mainnet bytecode (ADR 0013).

**Pinned by:** `test/unit/EscapePath.t.sol`, `test_Escape_DirtyAddressArgumentGetsNoFastPath`.

**General lesson.** Unit tests on a locally compiled Safe are not evidence about how the deployed
Safe handles input. Every property that depends on decoding or validation is asserted against the
deployed bytecode.

## 2. `safeTxGas` cannot make the inner call fail when `gasPrice == 0` (Phase 4)

**Finding.** With `gasPrice == 0`, the Safe forwards `gasleft() - 2500` to the inner call and
ignores `safeTxGas` (`lib/safe-smart-account/contracts/Safe.sol:180`). `safeTxGas` only matters for
whether a failed inner call reverts the whole transaction (`Safe.sol:184`). The firewall bans
refunds (ADR 0010), so `gasPrice` is always 0.

**Why it matters.** "Consume only on success" (ADR 0023, D7) can't be tested by starving the inner
call of gas. The test uses a target whose inner call reverts instead (`SafeRefusingGuard`), with a
non-zero `safeTxGas`.

**Pinned by:** `test_Escape_NotConsumedWhenSetGuardFails`.

## 3. `makeAddr` addresses can have code on mainnet (Phase 3)

**Finding.** Foundry's `makeAddr("alice")` address has an EIP-7702 delegation on mainnet that
forwards ETH. Tests that treat it as an EOA silently test something else on the fork variant.

**What it changed.** All test recipients use `_eoa(label)`. The Phase 6 allowlist must never rely
on a recipient being code-free (`docs/threat-model.md` §8).
