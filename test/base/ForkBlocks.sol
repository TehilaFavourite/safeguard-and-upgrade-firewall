// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Pinned mainnet fork blocks (ADR 0013). Every value below was read from mainnet through
///         an archive node on 2026-10-14, not taken from memory.
library ForkBlocks {
    /// @dev Feature and infra fork tests. This was the latest mainnet block when pinned. Canonical
    ///      Safe v1.5.0 contracts exist here: the earliest of them (SafeProxyFactory) first has code
    ///      at block 22774977, and the Safe singleton at 22838493 (found by bisecting `eth_getCode`).
    uint256 internal constant FEATURE = 26_191_601;

    /// @dev Phase 11 Bybit replay. Last block before the hack: the Bybit cold wallet
    ///      (0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4) still has singleton
    ///      0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F, `VERSION()` = "1.1.1", threshold 3 of 6,
    ///      nonce 71. Slot 0 changes in block 21895238 (tx
    ///      0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882, 2025-02-21 14:13:35 UTC).
    ///      The canonical v1.5.0 contracts do **not** exist yet at this block, so the Phase 11 demo
    ///      deploys them itself. It must not use the canonical-address ForkSafe harness.
    uint256 internal constant BYBIT_PRE_HACK = 21_895_237;
}
