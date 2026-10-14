// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Safe} from "safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {CompatibilityFallbackHandler} from "safe-smart-account/contracts/handler/CompatibilityFallbackHandler.sol";
import {MultiSendCallOnly} from "safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";
import {MultiSend} from "safe-smart-account/contracts/libraries/MultiSend.sol";

import {FirewallTestBase} from "./FirewallTestBase.sol";

/// @notice Unit variant: Safe v1.5.0 sources compiled locally with solc 0.8.28 (ADR 0013).
abstract contract LocalSafe is FirewallTestBase {
    function _deploySafe() internal override returns (SafeInfra memory i) {
        i.singleton = address(new Safe());
        i.proxyFactory = address(new SafeProxyFactory());
        i.fallbackHandler = address(new CompatibilityFallbackHandler());
        i.multiSendCallOnly = address(new MultiSendCallOnly());
        i.multiSend = address(new MultiSend());
        // Phase 1 only stores this address. Phases that need Permit2 behaviour will deploy a mock.
        i.permit2 = makeAddr("permit2");
    }
}
