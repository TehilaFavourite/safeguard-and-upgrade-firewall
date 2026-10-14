// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {ForkSafe} from "../base/ForkSafe.t.sol";
import {Forwarder} from "../mocks/Forwarder.sol";
import {TestModule} from "../mocks/TestModule.sol";
import {SequenceExecutor} from "../mocks/SequenceExecutor.sol";
import {Reverter} from "../mocks/Reverter.sol";

/// @notice I1.6 (nested pre-hooks revert) and I1.7 (flag cleared after every outcome) (ADR 0005).
abstract contract ReentrancyTest is FirewallTestBase {
    Forwarder internal forwarder;
    SequenceExecutor internal sequencer;
    address internal recipient;

    function setUp() public virtual override {
        super.setUp();
        forwarder = new Forwarder();
        sequencer = new SequenceExecutor();
        recipient = makeAddr("recipient");
    }

    // ---------------------------------------------------------------- I1.6 nested executions

    /// @dev Outer signed tx (nonce n) calls the Forwarder, which calls safe.execTransaction for
    ///      nonce n + 1. Safe increments the nonce before execution (Safe.sol:145) and bubbles the
    ///      inner revert when safeTxGas == 0 (Safe.sol:184-191).
    function test_Reentrancy_NestedExecTransactionReverts() public {
        uint256 n = safe.nonce();
        bytes memory inner = _signedExecCalldata(recipient, 0, "", Enum.Operation.Call, 0, n + 1);
        bytes memory outerData = abi.encodeCall(Forwarder.forward, (address(safe), inner));

        vm.expectRevert(
            abi.encodeWithSelector(ISafeFirewallGuard.Reentrancy.selector, ISafeFirewallGuard.ExecutionPath.SIGNED)
        );
        _execSigned(address(forwarder), 0, outerData, Enum.Operation.Call);
    }

    /// @dev Outer signed tx calls the module, which calls execTransactionFromModule. The module
    ///      pre-hook reverts before execution (ModuleManager.sol:107), so the revert propagates.
    function test_Reentrancy_ModuleTxInsideSignedTxReverts() public {
        bytes memory moduleCall = abi.encodeCall(TestModule.exec, (safe, recipient, 0, "", Enum.Operation.Call));

        vm.expectRevert(
            abi.encodeWithSelector(ISafeFirewallGuard.Reentrancy.selector, ISafeFirewallGuard.ExecutionPath.SIGNED)
        );
        _execSigned(address(module), 0, moduleCall, Enum.Operation.Call);
    }

    /// @dev Module tx calls the Forwarder, which calls safe.execTransaction. The module path does
    ///      not bubble inner failures (ModuleManager.sol:175), so the call returns (false, revertData).
    function test_Reentrancy_SignedTxInsideModuleTxReverts() public {
        bytes memory inner = _signedExecCalldata(recipient, 0, "", Enum.Operation.Call, 0, safe.nonce());
        bytes memory fwd = abi.encodeCall(Forwarder.forward, (address(safe), inner));

        (bool success, bytes memory returnData) =
            module.execReturnData(safe, address(forwarder), 0, fwd, Enum.Operation.Call);

        assertFalse(success, "nested signed tx must fail");
        assertEq(
            returnData,
            abi.encodeWithSelector(ISafeFirewallGuard.Reentrancy.selector, ISafeFirewallGuard.ExecutionPath.MODULE)
        );
    }

    // ---------------------------------------------------------------- I1.7 flag cleared

    function test_Reentrancy_TwoSequentialExecutionsInOneTxPass() public {
        uint256 n = safe.nonce();
        SequenceExecutor.Step[] memory steps = new SequenceExecutor.Step[](2);
        steps[0] =
            SequenceExecutor.Step(address(safe), _signedExecCalldata(recipient, 1 wei, "", Enum.Operation.Call, 0, n));
        steps[1] = SequenceExecutor.Step(
            address(safe), _signedExecCalldata(recipient, 1 wei, "", Enum.Operation.Call, 0, n + 1)
        );

        bool[] memory ok = sequencer.run(steps);

        assertTrue(ok[0] && ok[1], "both executions must succeed");
        assertEq(safe.nonce(), n + 2);
    }

    /// @dev A guard revert rolls back the whole execution, including transient writes, so the next
    ///      execution in the same Ethereum transaction (same nonce) is unaffected.
    function test_Reentrancy_FlagNotStuckAfterBlockedTx() public {
        uint256 n = safe.nonce();
        SequenceExecutor.Step[] memory steps = new SequenceExecutor.Step[](2);
        // Blocked: every top-level call to the guard reverts in Phase 1 (I1.12).
        steps[0] =
            SequenceExecutor.Step(address(safe), _signedExecCalldata(address(guard), 0, "", Enum.Operation.Call, 0, n));
        steps[1] =
            SequenceExecutor.Step(address(safe), _signedExecCalldata(recipient, 1 wei, "", Enum.Operation.Call, 0, n));

        bool[] memory ok = sequencer.run(steps);

        assertFalse(ok[0], "first execution must be blocked");
        assertTrue(ok[1], "second execution must not see a stuck flag");
    }

    /// @dev With safeTxGas != 0 a failing inner call does not revert (Safe.sol:184). The post-hook
    ///      runs with success == false and must still clear the flag.
    function test_Reentrancy_FlagNotStuckAfterInnerCallFailure() public {
        address reverter = address(new Reverter());
        uint256 n = safe.nonce();
        SequenceExecutor.Step[] memory steps = new SequenceExecutor.Step[](2);
        steps[0] = SequenceExecutor.Step(
            address(safe), _signedExecCalldata(reverter, 0, "", Enum.Operation.Call, NON_ZERO_SAFE_TX_GAS, n)
        );
        steps[1] = SequenceExecutor.Step(
            address(safe), _signedExecCalldata(recipient, 1 wei, "", Enum.Operation.Call, 0, n + 1)
        );

        bool[] memory ok = sequencer.run(steps);

        assertTrue(ok[0], "execTransaction returns (not reverts) when the inner call fails with safeTxGas > 0");
        assertTrue(ok[1], "second execution must not see a stuck flag");
        assertEq(safe.nonce(), n + 2);
    }
}

contract ReentrancyUnitTest is ReentrancyTest, LocalSafe {
    function setUp() public override(ReentrancyTest, FirewallTestBase) {
        ReentrancyTest.setUp();
    }
}

contract ReentrancyForkTest is ReentrancyTest, ForkSafe {
    function setUp() public override(ReentrancyTest, FirewallTestBase) {
        ReentrancyTest.setUp();
    }
}
