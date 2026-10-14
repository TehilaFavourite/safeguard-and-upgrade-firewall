// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {FirewallTestBase} from "./FirewallTestBase.sol";

/// @notice Fork variant: the deployed mainnet Safe v1.5.0 contracts at a pinned block (ADR 0013).
abstract contract ForkSafe is FirewallTestBase {
    /// @dev Pinned mainnet block. Set to the latest block once ETH_RPC_URL is available. While it
    ///      is 0, the fork variant skips, and says so in the output.
    uint256 internal constant FORK_BLOCK = 0;

    // Canonical Safe v1.5.0 addresses, from lib/safe-smart-account/CHANGELOG.md
    address internal constant SAFE_SINGLETON = 0xFf51A5898e281Db6DfC7855790607438dF2ca44b; // :25
    address internal constant SAFE_PROXY_FACTORY = 0x14F2982D601c9458F93bd70B218933A6f8165e7b; // :32
    address internal constant COMPATIBILITY_FALLBACK_HANDLER = 0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4; // :39
    address internal constant MULTISEND_CALL_ONLY = 0xA83c336B20401Af773B6219BA5027174338D1836; // :48
    // Permit2 is not part of the Safe repository. Source citation pending (see the Phase 1 report);
    // the fork setup checks that code exists here.
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    uint256 internal constant MAINNET_CHAIN_ID = 1;

    error MissingCode(string name, address at);
    error WrongChain(uint256 chainId);

    function _deploySafe() internal override returns (SafeInfra memory i) {
        string memory rpc = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(rpc).length == 0 || FORK_BLOCK == 0) {
            vm.skip(true, "fork variant skipped: ETH_RPC_URL unset or FORK_BLOCK not pinned");
            return i;
        }
        // "mainnet" is the [rpc_endpoints] alias in foundry.toml, which reads ETH_RPC_URL from .env.
        vm.createSelectFork("mainnet", FORK_BLOCK);
        if (block.chainid != MAINNET_CHAIN_ID) revert WrongChain(block.chainid);

        _requireCode("Safe singleton", SAFE_SINGLETON);
        _requireCode("SafeProxyFactory", SAFE_PROXY_FACTORY);
        _requireCode("CompatibilityFallbackHandler", COMPATIBILITY_FALLBACK_HANDLER);
        _requireCode("MultiSendCallOnly", MULTISEND_CALL_ONLY);
        _requireCode("Permit2", PERMIT2);

        i.singleton = SAFE_SINGLETON;
        i.proxyFactory = SAFE_PROXY_FACTORY;
        i.fallbackHandler = COMPATIBILITY_FALLBACK_HANDLER;
        i.multiSendCallOnly = MULTISEND_CALL_ONLY;
        i.permit2 = PERMIT2;
    }

    function _requireCode(string memory name, address at) private view {
        if (at.code.length == 0) revert MissingCode(name, at);
    }
}
