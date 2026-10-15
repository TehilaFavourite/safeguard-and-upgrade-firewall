# Factory Size Plan (not implemented)

**Status:** plan only. **Trigger:** implement when the factory's EIP-170 headroom drops below
**4 KB**, i.e. a `GuardFactory` runtime above 20,480 B in `script/check-contract-sizes.sh`. As of
Phase 4 it is 15,763 B (8,813 B headroom).

## Problem

`GuardFactory` uses `new SafeFirewallGuard{salt: ...}(config)`, so its runtime embeds the guard's
full creation code. That makes the factory, not the guard, the first contract to hit EIP-170
(24,576 B): its size is roughly the guard's init code plus about 1.3 KB. The guard is held to
22,000 B only because of this.

## Plan

1. **The factory stores only `GUARD_INITCODE_HASH`**, the `keccak256` of the guard's creation code
   **without** constructor arguments. It is pinned at build time, not computed from
   `type(SafeFirewallGuard).creationCode` inside the factory, which would embed the code again. A
   test asserts `GUARD_INITCODE_HASH == keccak256(type(SafeFirewallGuard).creationCode)`; the test
   contract embeds the code, the factory doesn't. The deploy script asserts the same value.
2. **`deploy(config, initCode)`:**
   - reverts with `InitCodeMismatch` unless `keccak256(initCode) == GUARD_INITCODE_HASH`;
   - computes `salt = keccak256(abi.encode(config.safe, VERSION))`, unchanged (ADR 0007);
   - CREATE2s `initCode ++ abi.encode(config)`;
   - reverts if CREATE2 returns 0, and emits `GuardDeployed` as now.
3. **The guard gets the full budget:** EIP-170 (24,576 B runtime) and EIP-3860 (49,152 B init
   code). The guard's size gate rises from 22,000 B to 24,576 B, minus whatever margin the owner
   picks.

## Effect on `predict()`

**The current signature `predict(config)` can't be kept with this plan as written.** The CREATE2
address depends on `keccak256(initCode ++ abi.encode(config))`, and that can't be derived from
`keccak256(initCode)`. Options, for the owner to decide when the trigger fires:

- **A. `predict(config, initCode)`.** The caller supplies the init code and the factory verifies
  its hash first. Simple. The cost is that every caller (deploy script, install batch builder, alert
  bot) needs the init code, about 14 KB.
- **B. Move the config out of the init code.** The init code takes no constructor arguments, so
  its hash is the CREATE2 init-code hash; `GUARD_INITCODE_HASH` is then enough, and
  `predict(config)` stays. The config goes into the salt
  (`salt = keccak256(abi.encode(config.safe, VERSION, keccak256(abi.encode(config))))`), so the
  address still commits to the full config (ADR 0007). The guard's constructor reads the config back
  from the factory: the factory holds it in transient storage for the duration of `deploy`, and the
  constructor STATICCALLs `msg.sender`. This is the Uniswap v3 pool-deployer pattern.
  - (−) The constructor trusts `msg.sender` to be the real factory. A deployment through any other
    deployer gets a different address, so it can't impersonate the predicted guard. But the deploy
    script and I4.20 have to keep checking the codehash, not just the address.
  - (−) Amends ADR 0007 (salt contents) and the "constructor-only config" wording, though the
    config is still fixed at construction with no initializer.
- **C. Off-chain prediction only.** `predict` is removed and tooling computes the address.
  (−) Loses the on-chain view that the install batch and tests rely on.

## Permissionless and idempotent deploy rules (ADR 0007), under the plan

- **Permissionless:** anyone may call `deploy(config, initCode)`. A front-runner can only deploy
  the identical guard: the hash check pins the code, and the salt and arguments pin the config.
- **Idempotent:** if code already exists at the predicted address, return it without redeploying
  or emitting. For option A, the hash check runs **before** the early return, so a wrong
  `initCode` always reverts, even for an existing guard. That keeps the return value a function of
  `config` alone.
- **Escape replacements** are still deployed outside the Safe (ADR 0014). I4.20 still binds the
  replacement by address and `extcodehash`, so nothing in the escape path changes.

## Costs

- Calldata: about 14 KB of init code per `deploy` call. That is roughly 230k gas at 16 gas per
  non-zero byte, more under the EIP-7623 calldata floor. It is paid once per Safe at install, and
  once per replacement guard.
- The install batch (spec, Install step 0) carries the init code inside a `MultiSendCallOnly`
  entry. The batch decoder bounds (ADR 0003) don't limit entry size, so no change is needed there.

## Not changing

The guard's code, its storage, and the escape path and its binding checks.
