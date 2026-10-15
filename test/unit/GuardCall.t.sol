// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {IModuleGuard} from "safe-smart-account/contracts/base/ModuleManager.sol";
import {IERC165} from "safe-smart-account/contracts/interfaces/IERC165.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";

/// @notice I1.12 / I4.19: a top-level call with `to == GUARD` reverts unless its selector is on the
///         closed list of guard functions the Safe may call (ADR 0018). Batch inner calls are covered in
///         BatchPolicy.t.sol, module calls below. I1.11: anything else passes until the allowlist
///         (scaffolding only).
abstract contract GuardCallTest is FirewallTestBase {
    /// @dev The closed list (I4.19, ADR 0023): the only guard selectors a signed Safe call may target.
    function _permitted() internal pure returns (bytes4[5] memory) {
        return [
            ISafeFirewallGuard.queueEscape.selector,
            ISafeFirewallGuard.cancelEscape.selector,
            ISafeFirewallGuard.queueGuardianChange.selector,
            ISafeFirewallGuard.executeGuardianChange.selector,
            ISafeFirewallGuard.cancel.selector
        ];
    }

    function _isPermitted(bytes4 sel) internal pure returns (bool) {
        bytes4[5] memory p = _permitted();
        for (uint256 i = 0; i < p.length; i++) {
            if (p[i] == sel) return true;
        }
        return false;
    }

    function _rejection(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(ISafeFirewallGuard.GuardCallRejected.selector, selector);
    }

    // ---------------------------------------------------------------- I1.12 signed path

    function test_GuardCall_SignedHookSelectorsRevert() public {
        bytes[4] memory calls = [
            abi.encodeCall(
                ITransactionGuard.checkTransaction,
                (address(0), 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0))
            ),
            abi.encodeCall(ITransactionGuard.checkAfterExecution, (bytes32(0), true)),
            abi.encodeCall(IModuleGuard.checkModuleTransaction, (address(0), 0, "", Enum.Operation.Call, address(0))),
            abi.encodeCall(IModuleGuard.checkAfterModuleExecution, (bytes32(0), true))
        ];
        for (uint256 i = 0; i < calls.length; i++) {
            _execSignedExpectRevert(address(guard), 0, calls[i], Enum.Operation.Call, _rejection(bytes4(calls[i])));
        }
    }

    function testFuzz_GuardCall_SignedAnySelectorReverts(bytes calldata data) public {
        vm.assume(data.length >= 4 && !_isPermitted(bytes4(data[:4])));
        _execSignedExpectRevert(address(guard), 0, data, Enum.Operation.Call, _rejection(bytes4(data[:4])));
    }

    function test_GuardCall_SignedEmptyCalldataReverts() public {
        _execSignedExpectRevert(address(guard), 0, "", Enum.Operation.Call, _rejection(bytes4(0)));
    }

    function test_GuardCall_SignedDelegatecallToGuardReverts() public {
        bytes memory data = abi.encodeCall(ITransactionGuard.checkAfterExecution, (bytes32(0), true));
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory expected = _rejection(bytes4(data)); // intended: the first 4 bytes are the selector
        _execSignedExpectRevert(address(guard), 0, data, Enum.Operation.DelegateCall, expected);
    }

    // ---------------------------------------------------------------- I4.19 the closed list

    /// @dev Every other guard function, including all hooks, the guardian's and the views, is rejected
    ///      when the Safe targets it.
    function test_GuardCall_NonPermittedGuardFunctionsRejected() public {
        bytes4[10] memory rejected = [
            ITransactionGuard.checkTransaction.selector,
            ITransactionGuard.checkAfterExecution.selector,
            IModuleGuard.checkModuleTransaction.selector,
            IModuleGuard.checkAfterModuleExecution.selector,
            ISafeFirewallGuard.guardianCancel.selector,
            ISafeFirewallGuard.markExpired.selector,
            ISafeFirewallGuard.guardian.selector,
            ISafeFirewallGuard.getItem.selector,
            ISafeFirewallGuard.SAFE.selector,
            IERC165.supportsInterface.selector
        ];
        for (uint256 i = 0; i < rejected.length; i++) {
            assertFalse(_isPermitted(rejected[i]), "a hook or non-Safe function is on the permitted list");
            _execSignedExpectRevert(
                address(guard),
                0,
                abi.encodePacked(rejected[i], bytes32(0)),
                Enum.Operation.Call,
                abi.encodeWithSelector(ISafeFirewallGuard.GuardCallRejected.selector, rejected[i])
            );
        }
    }

    /// @dev Permitted selectors pass step 7. Their own checks run next, so the revert, if any, is not
    ///      GuardCallRejected. `cancel` of an unknown id is used as the probe.
    function test_GuardCall_PermittedSelectorPassesStep7() public {
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.cancel, (bytes32(uint256(1)))),
            Enum.Operation.Call,
            abi.encodeWithSelector(
                ISafeFirewallGuard.ItemNotQueued.selector, bytes32(uint256(1)), ISafeFirewallGuard.ItemStatus.NONE
            )
        );
    }

    /// @dev On the module path, even permitted selectors are rejected (ADR 0014).
    function test_GuardCall_ModulePathRejectsPermittedSelectors() public {
        bytes4[5] memory p = _permitted();
        for (uint256 i = 0; i < p.length; i++) {
            vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.GuardCallRejected.selector, p[i]));
            module.exec(safe, address(guard), 0, abi.encodePacked(p[i], bytes32(0)), Enum.Operation.Call);
        }
    }

    // ---------------------------------------------------------------- I1.12 module path

    /// @dev The module pre-hook reverts before execution (ModuleManager.sol:107), so the revert
    ///      propagates through the module.
    function test_GuardCall_ModuleCallReverts() public {
        bytes memory data = abi.encodeCall(ITransactionGuard.checkAfterExecution, (bytes32(0), true));
        // forge-lint: disable-next-line(unsafe-typecast)
        vm.expectRevert(_rejection(bytes4(data))); // intended: the first 4 bytes are the selector
        module.exec(safe, address(guard), 0, data, Enum.Operation.Call);
    }

    // ---------------------------------------------------------------- I1.11 scaffolding

    /// @dev Scaffolding: until the allowlist exists, ordinary calls are allowed. Phase 2 adds no
    ///      allowlist (refunds, delegatecall policy and protected state don't affect a plain ETH
    ///      transfer), so this test keeps passing until Phase 6, where the allowlist (P2) makes it
    ///      fail. It is deleted then, under the red-before-green rule in docs/test-plan.md.
    function test_Skeleton_AllowsOrdinaryCall() public {
        address recipient = _eoa("recipient");
        assertTrue(_execSigned(recipient, 1 ether, "", Enum.Operation.Call));
        assertEq(recipient.balance, 1 ether);
    }
}

contract GuardCallUnitTest is GuardCallTest, LocalSafe {}

/// forge-config: default.fuzz.runs = 64
contract GuardCallForkTest is GuardCallTest, FeatureForkSafe {}
