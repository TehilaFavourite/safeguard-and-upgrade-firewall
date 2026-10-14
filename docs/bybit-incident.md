# Bybit Incident: On-Chain Evidence

This is the evidence base for the README and the Phase 11 demo. Every fact was read from Ethereum
mainnet through an archive node on 2026-10-14, and comes with the exact command that reproduces it.

**Setup:** run the commands from the repository root with a mainnet archive endpoint in `.env`.
`--rpc-url mainnet` is the `[rpc_endpoints]` alias in `foundry.toml`. Confirm the chain first:

```sh
cast chain-id --rpc-url mainnet            # 1
```

## Summary

| Fact | Value |
|---|---|
| Bybit cold wallet (Safe proxy) | `0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4` |
| Last block before the hack | 21,895,237 |
| Hack block | 21,895,238 |
| Hack transaction | `0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882` |
| Time | 2025-02-21 14:13:35 UTC (block timestamp 1740147215) |
| Singleton before (slot 0) | `0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F` |
| `VERSION()` before | `"1.1.1"` |
| Owners / threshold before | 6 owners, threshold 3 |
| Nonce before | 71 |
| ETH balance before | 401,346.768858404671846374 ETH |
| Slot 0 after | `0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516` |

## 1. Slot 0 (the singleton) before and after

The Safe proxy's slot 0 holds its singleton address. It changes between blocks 21,895,237 and
21,895,238:

```sh
B=0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4
cast storage ${B} 0 --block 21895237 --rpc-url mainnet
# 0x00000000000000000000000034cfac646f301356faa8b21e94227e3583fe3f5f
cast storage ${B} 0 --block 21895238 --rpc-url mainnet
# 0x000000000000000000000000bdd077f651ebe7f7b3ce16fe5f2b025be2969516
```

Block 21,895,238 was found by bisecting `cast storage ${B} 0 --block <n>` between block 21,000,000
and the latest block.

## 2. Version and state before the hack

```sh
cast call 0x34cfac646f301356faa8b21e94227e3583fe3f5f 'VERSION()(string)' --rpc-url mainnet
# "1.1.1"
cast call ${B} 'VERSION()(string)'          --block 21895237 --rpc-url mainnet   # "1.1.1"
cast call ${B} 'getThreshold()(uint256)'    --block 21895237 --rpc-url mainnet   # 3
cast call ${B} 'nonce()(uint256)'           --block 21895237 --rpc-url mainnet   # 71
cast call ${B} 'getOwners()(address[])'     --block 21895237 --rpc-url mainnet
cast balance ${B} --block 21895237 --ether --rpc-url mainnet                      # 401346.768858404671846374
```

**Owners at block 21,895,237**, in the order `getOwners()` returns them:

1. `0x1F4EB0a903619ac168b19A82F1a6e2e426522211`
2. `0x828424517F9F04015db02169f4026D57B2B07229`
3. `0x3Cc3A225769900e003E264dd4CB43E90896BC21A`
4. `0x2cDD560058D5ac32dc416AAa09Eaf93230c0B7B3`
5. `0xD367f8322b64F29faF71dDB5c1877dC9ED6EC644`
6. `0xe3dF2cCEAc61B1aFA311372ecC5B40A3A6585a9E`

Safe v1.1.1 has no guard support. Guards first appear in v1.3.0
(`git -C lib/safe-smart-account grep -l checkAfterExecution v1.3.0 -- contracts`; ADR 0001).

## 3. The hack transaction

It is the only transaction in block 21,895,238 whose `to` is the Bybit Safe:

```sh
cast block 21895238 --full --json --rpc-url mainnet \
  | jq -r --arg b "${B}" '.transactions[] | select((.to // "" | ascii_downcase) == $b) | "\(.hash) from=\(.from) selector=\(.input[0:10])"'
# 0x46deef0f…7882 from=0x0fa09c3a328792253f8dee7116848723b72a6d2e selector=0x6a761202
cast block 21895238 --field timestamp --rpc-url mainnet   # 1740147215
```

Selector `0x6a761202` is `execTransaction`.

## 4. The decoded payload

```sh
IN=$(cast tx 0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882 input --rpc-url mainnet)
cast decode-calldata 'execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)' ${IN}
```

| Parameter | Value |
|---|---|
| `to` | `0x96221423681A6d52E184D440a8eFCEbB105C7242` |
| `value` | 0 |
| `data` | `0xa9059cbb` + `bdd077f6…9516` + `0` |
| `operation` | **1 (DelegateCall)** |
| `safeTxGas` | 45746 |
| `baseGas`, `gasPrice` | 0, 0 |
| `gasToken`, `refundReceiver` | `0x0`, `0x0` |

```sh
cast 4byte 0xa9059cbb   # transfer(address,uint256)
```

**What the signers saw versus what ran.** The calldata looks like an ERC-20
`transfer(0xbdd0…9516, 0)`. With `operation = 1`, the Safe *delegatecalls* `0x9622…7242`, so that
contract's `transfer` runs in the Safe's own storage. Section 1 shows slot 0 afterwards equals the
`transfer` recipient argument, `0xbdd0…9516`. The Safe's singleton was replaced.

## 5. What this means for the demo (ADR 0013)

- **Canonical Safe v1.5.0 contracts don't exist at the pre-hack block.** They first have code at
  blocks 22,774,977–22,838,493, so the demo deploys v1.5.0 itself on the pre-hack fork:

  ```sh
  cast code 0x14F2982D601c9458F93bd70B218933A6f8165e7b --block 21895237 --rpc-url mainnet   # 0x (SafeProxyFactory)
  cast code 0xFf51A5898e281Db6DfC7855790607438dF2ca44b --block 21895237 --rpc-url mainnet   # 0x (Safe singleton)
  ```
- **The original signatures can't be replayed after migration.** The v1.1.1 domain separator has
  no chain ID; v1.5.0's does (ADR 0001, threat model §8).
- **Claim:** "the guard blocks this class of attack", not "this would have saved Bybit".
