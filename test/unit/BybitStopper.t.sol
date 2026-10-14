// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";
import {SafeFirewallGuardHarness} from "../harness/SafeFirewallGuardHarness.sol";
import {PreCheckOnlyGuard, PostCheckOnlyGuard} from "../harness/SeamGuards.sol";
import {BybitStyleDelegate, DelegateProbe} from "../mocks/StateMutators.sol";
import {BybitPayload} from "../fixtures/BybitPayload.sol";

/// @notice The decoded Bybit payload (docs/bybit-incident.md §4) against the guard:
///         I2.19 pre-check alone, I2.20 post-check alone, I2.21 both. Delegate: a faithful mock in
///         the unit variant, and the real attacker contract in the fork variant.
abstract contract BybitStopperBase is FirewallTestBase {
    // lib/safe-smart-account/contracts/libraries/SafeStorage.sol:11
    bytes32 internal constant SINGLETON_SLOT = bytes32(uint256(0));

    address internal delegate;

    function _bybitDelegate() internal virtual returns (address);

    function setUp() public virtual override {
        super.setUp();
        delegate = _bybitDelegate();
    }

    /// @dev The hack transaction's parameters: to, value 0, data, DelegateCall, safeTxGas 45746, no refunds.
    function _payload() internal view returns (SafeTx memory t) {
        t = _safeTx(delegate, 0, BybitPayload.data(), Enum.Operation(BybitPayload.OPERATION));
        t.safeTxGas = BybitPayload.SAFE_TX_GAS;
    }

    function _singletonSlot() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(safe), SINGLETON_SLOT))));
    }
}

/// @dev Unit variant delegate: the mock.
abstract contract LocalBybitDelegate is BybitStopperBase {
    function _bybitDelegate() internal override returns (address) {
        return address(new BybitStyleDelegate());
    }
}

/// @dev Fork variant delegate: the real attacker contract at its mainnet address.
abstract contract RealBybitDelegate is BybitStopperBase {
    function _bybitDelegate() internal pure override returns (address) {
        return BybitPayload.ATTACKER_DELEGATE;
    }
}

/// @notice I2.19: the comparison is disabled, and the pre-check alone stops the payload.
abstract contract BybitPreCheckOnlyTest is BybitStopperBase {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        virtual
        override
        returns (SafeFirewallGuardHarness)
    {
        return new PreCheckOnlyGuard(config);
    }

    function test_Bybit_PreCheckAloneBlocksPayload() public {
        uint256 n = safe.nonce();
        address singletonBefore = _singletonSlot();

        // The delegate is never reached. expectCall also counts delegatecalls (checked separately).
        vm.expectCall(delegate, BybitPayload.data(), 0);
        _execTxExpectRevert(
            _payload(), abi.encodeWithSelector(ISafeFirewallGuard.DelegateCallNotAllowed.selector, delegate)
        );

        assertEq(_singletonSlot(), singletonBefore, "slot 0 changed");
        assertEq(safe.nonce(), n, "nonce changed");
    }
}

/// @notice I2.20: the operation policy is disabled, and the post-check alone stops the payload.
abstract contract BybitPostCheckOnlyTest is BybitStopperBase {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        virtual
        override
        returns (SafeFirewallGuardHarness)
    {
        return new PostCheckOnlyGuard(config);
    }

    function test_Bybit_PostCheckAloneBlocksPayload() public {
        uint256 n = safe.nonce();
        address singletonBefore = _singletonSlot();

        // The delegate IS reached: the payload executes and rewrites slot 0, then the post-check reverts.
        vm.expectCall(delegate, BybitPayload.data(), 1);
        _execTxExpectRevert(
            _payload(),
            _changed(
                ISafeFirewallGuard.ProtectedField.SINGLETON,
                _b32(singletonBefore),
                _b32(BybitPayload.ATTACKER_SINGLETON)
            )
        );

        assertEq(_singletonSlot(), singletonBefore, "slot 0 must be restored by the revert");
        assertEq(safe.nonce(), n, "nonce changed");
    }
}

/// @notice I2.21: the full guard. The payload is stopped at the pre-check.
abstract contract BybitFullGuardTest is BybitStopperBase {
    function test_Bybit_FullGuardBlocksPayloadAtPreCheck() public {
        uint256 n = safe.nonce();
        address singletonBefore = _singletonSlot();

        vm.expectCall(delegate, BybitPayload.data(), 0);
        _execTxExpectRevert(
            _payload(), abi.encodeWithSelector(ISafeFirewallGuard.DelegateCallNotAllowed.selector, delegate)
        );

        assertEq(_singletonSlot(), singletonBefore);
        assertEq(safe.nonce(), n);
    }
}

contract BybitPreCheckOnlyUnitTest is BybitPreCheckOnlyTest, LocalBybitDelegate, LocalSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(BybitPreCheckOnlyTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return BybitPreCheckOnlyTest._newGuard(config);
    }

    function setUp() public override(BybitStopperBase, FirewallTestBase) {
        BybitStopperBase.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract BybitPreCheckOnlyForkTest is BybitPreCheckOnlyTest, RealBybitDelegate, FeatureForkSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(BybitPreCheckOnlyTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return BybitPreCheckOnlyTest._newGuard(config);
    }

    function setUp() public override(BybitStopperBase, FirewallTestBase) {
        BybitStopperBase.setUp();
    }
}

contract BybitPostCheckOnlyUnitTest is BybitPostCheckOnlyTest, LocalBybitDelegate, LocalSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(BybitPostCheckOnlyTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return BybitPostCheckOnlyTest._newGuard(config);
    }

    function setUp() public override(BybitStopperBase, FirewallTestBase) {
        BybitStopperBase.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract BybitPostCheckOnlyForkTest is BybitPostCheckOnlyTest, RealBybitDelegate, FeatureForkSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(BybitPostCheckOnlyTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return BybitPostCheckOnlyTest._newGuard(config);
    }

    function setUp() public override(BybitStopperBase, FirewallTestBase) {
        BybitStopperBase.setUp();
    }
}

contract BybitFullGuardUnitTest is BybitFullGuardTest, LocalBybitDelegate, LocalSafe {
    function setUp() public override(BybitStopperBase, FirewallTestBase) {
        BybitStopperBase.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract BybitFullGuardForkTest is BybitFullGuardTest, RealBybitDelegate, FeatureForkSafe {
    function setUp() public override(BybitStopperBase, FirewallTestBase) {
        BybitStopperBase.setUp();
    }
}

/// @notice Fork only: the mock used by the unit variant behaves like the real attacker contract. Both,
///         when delegatecalled with the hack calldata, write ATTACKER_SINGLETON into slot 0.
/// forge-config: default.fuzz.runs = 64
contract BybitDelegateFidelityForkTest is FeatureForkSafe {
    function test_Bybit_MockMatchesRealAttackerContract() public {
        bytes32 expected = bytes32(uint256(uint160(BybitPayload.ATTACKER_SINGLETON)));
        assertEq(new DelegateProbe().run(BybitPayload.ATTACKER_DELEGATE, BybitPayload.data()), expected, "real");
        assertEq(new DelegateProbe().run(address(new BybitStyleDelegate()), BybitPayload.data()), expected, "mock");
    }
}
