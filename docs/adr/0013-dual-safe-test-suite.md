# ADR 0013: One test suite, two Safe sources

- Status: Accepted
- Date: 2026-10-10

## Context

`foundry.toml` pins solc 0.8.28, so tests that deploy Safe from `lib/` run Safe v1.5.0 compiled with
0.8.28. The deployed v1.5.0 singleton was built with solc 0.7.6, optimizer disabled
(`lib/safe-smart-account/CHANGELOG.md:15,17`). Unit tests would therefore exercise different
bytecode than mainnet.

## Options

### A. Unit tests on the local build only; separate fork tests for the demo
- (−) Feature behaviour is never checked against the real singleton.

### B. Compile the Safe sources with 0.7.6 through Foundry's per-path compiler restrictions
- (+) Closer bytecode.
- (−) Still not the deployed artifact, and the build config is more complex.

### C. One suite, two Safe sources
An abstract base test exposes a `_deploySafe()` hook. The unit variant deploys the locally compiled
(0.8.28) Safe; the fork variant uses the real deployed v1.5.0 singleton from mainnet. Every feature
test runs against both.
- (+) Fast local iteration, plus every rule checked against production bytecode.
- (−) The fork variant needs an archive RPC and is slower.

## Decision

**Option C.** Solc stays at 0.8.28.

## Consequences

- Each feature test contract is written once against the abstract base, then instantiated twice:
  `...UnitTest` and `...ForkTest`.
- **Fork variant setup:**
  - pin a fork block number, so results are deterministic and RPC responses are cached;
  - create a proxy through the canonical v1.5.0 `SafeProxyFactory`
    (`0x14F2982D601c9458F93bd70B218933A6f8165e7b`), pointing at the v1.5.0 `Safe` singleton
    (`0xFf51A5898e281Db6DfC7855790607438dF2ca44b`). Both addresses are from `CHANGELOG.md`, and
    the fork setup must confirm code exists at each.
- **CI:** the forge-generated `.github/workflows/test.yml` runs `forge test`. Fork tests need an
  `ETH_RPC_URL` secret. Without one they must be skipped explicitly, not silently pass.

## Pinned addresses (owner, 2026-10-14)

- **Constructor immutables.** The canonical addresses (`MultiSendCallOnly`, `Permit2`, and the
  migration-related addresses per ADR 0015) are constructor arguments stored as immutables.
- **Tests:** unit tests deploy local instances; fork tests pass the mainnet addresses.
- **Deploy script:** before deploying, verifies each address's `extcodehash` against the recorded
  mainnet value.
- **No `vm.etch`** unless something truly must sit at a canonical address.

## Problem this resolves: pinned addresses differ between the variants

The guard pins canonical addresses: `MultiSendCallOnly` (ADR 0003), and the expected singleton
checked in the post-check. In the unit variant, locally deployed contracts have different
addresses, so either the tests or the guard have to adapt. Candidates:

- **Constructor parameters.** The guard takes these addresses as immutables, and the factory or
  deploy config supplies the canonical values. Tests pass local ones. Risk: a misconfigured
  deployment could pin the wrong contract, so the deploy script must assert the canonical values.
- **`vm.etch`.** The unit base copies locally compiled code to the canonical addresses, and the
  guard hard-codes them as constants. Risk: the unit variant then runs 0.8.28 code at an address
  whose real code is 0.7.6. That is acceptable, because the fork variant covers the real code.
