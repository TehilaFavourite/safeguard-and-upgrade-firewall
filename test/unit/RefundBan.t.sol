// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";

/// @notice I2.1-I2.3: refund fields must be zero on every signed transaction, checked at hook step 4,
///         before R2 and before step 7 (ADR 0010, ADR 0014).
abstract contract RefundBanTest is FirewallTestBase {
    address internal recipient;

    function setUp() public virtual override {
        super.setUp();
        recipient = _eoa("recipient");
    }

    function _refundError(uint256 gasPrice, address gasToken, address refundReceiver)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(ISafeFirewallGuard.RefundNotAllowed.selector, gasPrice, gasToken, refundReceiver);
    }

    // ---------------------------------------------------------------- I2.1 each field, and fuzz

    function test_Refunds_GasPriceNonZeroReverts() public {
        SafeTx memory t = _safeTx(recipient, 1 wei, "", Enum.Operation.Call);
        t.gasPrice = 1;
        _execTxExpectRevert(t, _refundError(1, address(0), address(0)));
    }

    function test_Refunds_GasTokenNonZeroReverts() public {
        address token = _eoa("gasToken");
        SafeTx memory t = _safeTx(recipient, 1 wei, "", Enum.Operation.Call);
        t.gasToken = token;
        _execTxExpectRevert(t, _refundError(0, token, address(0)));
    }

    function test_Refunds_RefundReceiverNonZeroReverts() public {
        address payable receiver = payable(_eoa("refundReceiver"));
        SafeTx memory t = _safeTx(recipient, 1 wei, "", Enum.Operation.Call);
        t.refundReceiver = receiver;
        _execTxExpectRevert(t, _refundError(0, address(0), receiver));
    }

    function testFuzz_Refunds_AnyNonZeroFieldReverts(uint256 gasPrice, address gasToken, address refundReceiver)
        public
    {
        vm.assume(gasPrice != 0 || gasToken != address(0) || refundReceiver != address(0));
        SafeTx memory t = _safeTx(recipient, 1 wei, "", Enum.Operation.Call);
        t.gasPrice = gasPrice;
        t.gasToken = gasToken;
        t.refundReceiver = payable(refundReceiver);
        _execTxExpectRevert(t, _refundError(gasPrice, gasToken, refundReceiver));
    }

    // ---------------------------------------------------------------- I2.2 hook order

    /// @dev A call to GUARD would hit step 7 (GuardCallRejected). Step 4 must win.
    function test_HookOrder_GuardCallWithRefundRevertsWithRefundError() public {
        SafeTx memory t = _safeTx(
            address(guard),
            0,
            abi.encodeCall(ITransactionGuard.checkAfterExecution, (bytes32(0), true)),
            Enum.Operation.Call
        );
        t.gasPrice = 1;
        _execTxExpectRevert(t, _refundError(1, address(0), address(0)));
    }

    /// @dev A cancellation-shaped transaction with a refund field set must not get R2's free pass.
    function test_HookOrder_CancellationShapedWithRefundRevertsWithRefundError() public {
        address payable receiver = payable(_eoa("refundReceiver"));
        SafeTx memory t = _safeTx(address(safe), 0, "", Enum.Operation.Call);
        t.refundReceiver = receiver;
        _execTxExpectRevert(t, _refundError(0, address(0), receiver));
    }

    // ---------------------------------------------------------------- I2.3 regression

    /// @dev `handlePayment` runs only when gasPrice > 0 (Safe.sol:196), so baseGas and safeTxGas
    ///      move no funds and stay unrestricted.
    function test_Refunds_BaseGasAndSafeTxGasAllowed() public {
        SafeTx memory t = _safeTx(recipient, 1 wei, "", Enum.Operation.Call);
        t.baseGas = 50_000;
        t.safeTxGas = NON_ZERO_SAFE_TX_GAS;
        assertTrue(_execTx(t));
        assertEq(recipient.balance, 1 wei);
    }
}

contract RefundBanUnitTest is RefundBanTest, LocalSafe {
    function setUp() public override(RefundBanTest, FirewallTestBase) {
        RefundBanTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract RefundBanForkTest is RefundBanTest, FeatureForkSafe {
    function setUp() public override(RefundBanTest, FirewallTestBase) {
        RefundBanTest.setUp();
    }
}
