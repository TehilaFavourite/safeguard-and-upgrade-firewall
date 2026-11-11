# Safeguard and Upgrade Firewall

A transaction guard and module guard for Safe v1.5.0 that blocks the kind of attack that drained the Bybit cold wallet in February 2025.

> **Status: work in progress (v1, phase 5 of 13).** Not audited and not ready to deploy. The allowlist, outflow caps and upgrade rules are not in place yet. See [Progress](#progress).

## The problem

On 21 February 2025 the Bybit cold wallet, a Safe with 6 owners and a threshold of 3, signed a transaction that looked routine. It was a `delegatecall` to an attacker's contract, and that call overwrote storage slot 0, the Safe's singleton (master copy) pointer. Once the singleton was swapped, the attacker controlled the wallet and moved about 401,000 ETH out.

The signers' approval was real. What failed was that nothing on chain checked what the transaction would actually do to the Safe before or after it ran. The on-chain evidence, with the commands to reproduce each fact from an archive node, is in [`docs/bybit-incident.md`](docs/bybit-incident.md).

## What the firewall does

One guard is deployed per Safe through a factory, with the Safe address fixed at deploy time. It hooks both the signed transaction path and the module path and applies the same checks to both.

Two rules shape everything:

- **P1:** an action is fast only if it reduces power and cannot stop the signers from reaching the threshold. Everything else goes through a timelock.
- **P2:** deny by default.

What it enforces:

- **Delegatecall restriction.** On the signed path, only the pinned `MultiSendCallOnly` contract. Modules can never delegatecall. This alone stops the Bybit payload.
- **Protected state check.** Before each transaction the guard snapshots the singleton, guard, module guard, fallback handler, module list, owners and threshold. After it runs, any change that a matured timelock item did not authorise reverts the transaction. This stops the Bybit payload independently of the delegatecall rule.
- **Strict batch decoding.** `MultiSendCallOnly` batches are parsed strictly (canonical encoding, every length in bounds, no trailing bytes), and every inner call gets the same checks as a top-level call.
- **Timelocked config.** Config changes are queued, wait out a delay (48h for config, 72h for the escape path), then execute. A guardian can cancel most items. Signers can cancel anything.
- **Escape path.** Signers can always remove or replace the guard after 72h, so a bug in the guard cannot lock the Safe forever.
- **Refund ban.** Gas refund fields must be zero, which closes a known way to pull funds through the refund mechanism.
- **Planned:** allowlist of targets and selectors, per-token outflow caps (token bucket), and timelocked proxy upgrades bound to the new implementation's code hash.

The full design is in [`docs/v1-spec.md`](docs/v1-spec.md), with the reasoning behind each decision in [`docs/adr/`](docs/adr/) and the threats it covers in [`docs/threat-model.md`](docs/threat-model.md).

## Progress

| Phase | Scope | Status |
|---|---|---|
| 0 | Traceability: every requirement mapped to a test | Done |
| 1 | Skeleton, factory, test harness for local and forked Safes | Done |
| 2 | Bybit stopper: delegatecall policy, refund ban, protected state check | Done |
| 3 | Strict MultiSend decoder with fuzzing and a differential test | Done |
| 4 | Timelock queue, escape path, guardian | Done |
| 5 | Self-call policy (owners, threshold, modules, guard changes) | In progress |
| 6 | Target and selector allowlist | Planned |
| 7 | Outflow caps (ETH and ERC-20, approvals) | Planned |
| 8 | Timelocked proxy upgrades | Planned |
| 9 | Install script and atomic install batch | Planned |
| 10 | Stateful invariant suite | Planned |
| 11 | Mainnet fork demo replaying the Bybit payload | Planned |
| 12 | Alert bot (Rust, alloy) | Planned |
| 13 | Final review and docs | Planned |

Details for each phase are in [`docs/build-plan.md`](docs/build-plan.md).

## Repository layout

```
src/
  SafeFirewallGuard.sol     the guard: hooks, policy, timelock, config
  GuardFactory.sol          CREATE2 deploy, one guard per Safe
  libraries/                MultiSend decoder, Safe slot helpers, bounds-checked memory reads
test/
  base/                     shared base; every test runs against a local Safe and a forked mainnet Safe
  unit/                     unit and fuzz tests, including BybitStopper.t.sol
  fork/                     fork infrastructure tests
  fixtures/                 the Bybit payload
script/                     CI gates: coverage, contract size, Slither, opcode checks
docs/                       spec, threat model, ADRs, test plan, findings, runbook
```

## Running the tests

Requires [Foundry](https://book.getfoundry.sh/). The toolchain is pinned to solc 0.8.28 (see ADR 0022).

```sh
git clone --recursive https://github.com/TehilaFavourite/safeguard-and-upgrade-firewall
cd safeguard-and-upgrade-firewall
forge build
forge test
```

Fork tests need a mainnet archive RPC endpoint:

```sh
echo "ETH_RPC_URL=<your archive node url>" > .env
forge test -j 1
```

## CI

Two jobs run in GitHub Actions:

- **unit:** format check, build, unit tests, coverage, gas snapshot check and Slither, on every push.
- **fork:** the full suite against forked mainnet Safes.

## Known limitations

- Targets Safe v1.5.0 on Ethereum mainnet, with ETH and ERC-20 only.
- Not audited. Do not use it to protect real funds.
- Until phases 6 to 8 are done, the guard does not limit ordinary calls or outflows.

## License

LGPL-3.0-only. See [`LICENSE`](LICENSE).
