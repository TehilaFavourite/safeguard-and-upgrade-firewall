// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ForkSafe} from "../base/ForkSafe.t.sol";

/// @notice I1.10: the fork variant runs against real mainnet code. ForkSafe already reverts in
///         setUp if any canonical contract has no code. This test makes that check visible as its
///         own result, and pins the Safe version string.
contract ForkInfraTest is ForkSafe {
    function test_ForkInfra_CanonicalContractsHaveCode() public view {
        assertGt(SAFE_SINGLETON.code.length, 0, "Safe singleton");
        assertGt(SAFE_PROXY_FACTORY.code.length, 0, "SafeProxyFactory");
        assertGt(COMPATIBILITY_FALLBACK_HANDLER.code.length, 0, "CompatibilityFallbackHandler");
        assertGt(MULTISEND_CALL_ONLY.code.length, 0, "MultiSendCallOnly");
        assertGt(PERMIT2.code.length, 0, "Permit2");
    }

    function test_ForkInfra_ProxyRunsSafeV150() public view {
        assertEq(safe.VERSION(), "1.5.0");
    }
}
