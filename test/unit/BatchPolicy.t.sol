// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {IFallbackManager} from "safe-smart-account/contracts/interfaces/IFallbackManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";
import {BatchEncoding} from "../helpers/BatchEncoding.sol";

/// @notice I3.9-I3.11, D2, D4 and "no fast paths inside a batch": batches through the real guard on a
///         real Safe (ADR 0003, ADR 0018).
abstract contract BatchPolicyTest is FirewallTestBase {
    address internal alice;
    address internal bob;

    function setUp() public virtual override {
        super.setUp();
        alice = _eoa("alice");
        bob = _eoa("bob");
    }

    function _execBatchExpectRevert(bytes memory packed, bytes memory revertData) internal {
        _execSignedExpectRevert(
            infra.multiSendCallOnly, 0, BatchEncoding.wrap(packed), Enum.Operation.DelegateCall, revertData
        );
    }

    // ---------------------------------------------------------------- I3.11 regression

    function test_Batch_WellFormedTransfersPass() public {
        bytes memory packed = abi.encodePacked(
            BatchEncoding.call(alice, 1 wei, ""),
            BatchEncoding.call(bob, 2 wei, ""),
            BatchEncoding.call(alice, 3 wei, "")
        );
        assertTrue(_execSigned(infra.multiSendCallOnly, 0, BatchEncoding.wrap(packed), Enum.Operation.DelegateCall));
        assertEq(alice.balance, 4 wei);
        assertEq(bob.balance, 2 wei);
    }

    // ---------------------------------------------------------------- D2: outer value

    function test_Batch_OuterValueNonZeroReverts() public {
        _execSignedExpectRevert(
            infra.multiSendCallOnly,
            1,
            BatchEncoding.wrap(BatchEncoding.call(alice, 1 wei, "")),
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(ISafeFirewallGuard.DelegateCallValueNotZero.selector, 1)
        );
    }

    // ---------------------------------------------------------------- D4: nested batch

    function test_Batch_NestedBatchReverts() public {
        bytes memory nested = BatchEncoding.wrap(BatchEncoding.call(alice, 1 wei, ""));
        bytes memory packed = abi.encodePacked(
            BatchEncoding.call(bob, 1 wei, ""), BatchEncoding.call(infra.multiSendCallOnly, 0, nested)
        );
        _execBatchExpectRevert(packed, abi.encodeWithSelector(ISafeFirewallGuard.NestedBatchNotAllowed.selector, 1));
    }

    // ---------------------------------------------------------------- I3.9 / I3.10: inner calls to GUARD

    /// @dev The ADR 0018 batch gap, flipped. In Phase 2 the inner checkAfterExecution reached the guard
    ///      mid-execution, and only the post-check backstop caught it, as
    ///      NoActiveExecution(SIGNED, NONE). From Phase 3 the pre-check rejects it.
    function test_Batch_InnerCallToGuardHookRevertsAtPreCheck() public {
        bytes memory hook = abi.encodeCall(ITransactionGuard.checkAfterExecution, (bytes32(0), true));
        _execBatchExpectRevert(
            BatchEncoding.call(address(guard), 0, hook),
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardCallRejected.selector, ITransactionGuard.checkAfterExecution.selector
            )
        );
    }

    function testFuzz_Batch_InnerCallToGuardAnySelectorReverts(bytes calldata data) public {
        vm.assume(data.length >= 4);
        _execBatchExpectRevert(
            BatchEncoding.call(address(guard), 0, data),
            abi.encodeWithSelector(ISafeFirewallGuard.GuardCallRejected.selector, bytes4(data[:4]))
        );
    }

    /// @dev Inner calldata shorter than 4 bytes reports a zero-padded selector, exactly as a top-level
    ///      call to GUARD does (test_GuardCall_SignedEmptyCalldataReverts).
    function test_Batch_InnerCallToGuardShortCalldataReportsPaddedSelector() public {
        _execBatchExpectRevert(
            BatchEncoding.call(address(guard), 0, ""),
            abi.encodeWithSelector(ISafeFirewallGuard.GuardCallRejected.selector, bytes4(0))
        );
        _execBatchExpectRevert(
            BatchEncoding.call(address(guard), 0, hex"abcd"),
            abi.encodeWithSelector(ISafeFirewallGuard.GuardCallRejected.selector, bytes4(0xabcd0000))
        );
    }

    /// @dev One bad entry reverts the whole batch: the good entry before it never runs.
    function test_Batch_OneBadEntryRevertsWholeBatch() public {
        bytes memory hook = abi.encodeCall(ITransactionGuard.checkAfterExecution, (bytes32(0), true));
        bytes memory packed =
            abi.encodePacked(BatchEncoding.call(alice, 1 wei, ""), BatchEncoding.call(address(guard), 0, hook));
        _execBatchExpectRevert(
            packed,
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardCallRejected.selector, ITransactionGuard.checkAfterExecution.selector
            )
        );
        assertEq(alice.balance, 0);
    }

    // ---------------------------------------------------------------- decoder errors surface through the guard

    function test_Batch_InnerDelegateCallRejectedByGuardNotMultiSend() public {
        _execBatchExpectRevert(
            BatchEncoding.entry(1, alice, 0, ""),
            abi.encodeWithSelector(ISafeFirewallGuard.InnerOperationNotAllowed.selector, 0, uint8(1))
        );
    }

    function test_Batch_EmptyBatchRejectedByGuard() public {
        _execBatchExpectRevert("", abi.encodeWithSelector(ISafeFirewallGuard.EmptyBatch.selector));
    }

    function test_Batch_TrailingBytesRejectedByGuard() public {
        bytes memory first = BatchEncoding.call(alice, 1 wei, "");
        _execBatchExpectRevert(
            abi.encodePacked(first, new bytes(20)),
            abi.encodeWithSelector(ISafeFirewallGuard.MultiSendMalformed.selector, first.length)
        );
    }

    // ---------------------------------------------------------------- no fast paths inside a batch

    /// @dev A cancellation-shaped inner entry (to == SAFE, value 0, empty data) must not set the
    ///      cancellation marker. If it did, the post-check would be skipped and the protected change in
    ///      the next entry would persist. Escape-shaped entries get the same test in Phase 4.
    function test_Batch_CancellationShapedEntryGetsNoFastPath() public {
        address newHandler = _eoa("newHandler");
        bytes memory packed = abi.encodePacked(
            BatchEncoding.call(address(safe), 0, ""),
            BatchEncoding.call(address(safe), 0, abi.encodeCall(IFallbackManager.setFallbackHandler, (newHandler)))
        );
        _execBatchExpectRevert(
            packed,
            _changed(ISafeFirewallGuard.ProtectedField.FALLBACK_HANDLER, _b32(infra.fallbackHandler), _b32(newHandler))
        );
    }

    /// @dev Same, with the cancellation-shaped entry written as `to == 0` (normalized to the Safe).
    function test_Batch_ZeroToCancellationShapedEntryGetsNoFastPath() public {
        address newHandler = _eoa("newHandler");
        bytes memory packed = abi.encodePacked(
            BatchEncoding.call(address(0), 0, ""),
            BatchEncoding.call(address(0), 0, abi.encodeCall(IFallbackManager.setFallbackHandler, (newHandler)))
        );
        _execBatchExpectRevert(
            packed,
            _changed(ISafeFirewallGuard.ProtectedField.FALLBACK_HANDLER, _b32(infra.fallbackHandler), _b32(newHandler))
        );
    }

    /// @dev Regression: a batch made only of cancellation-shaped entries runs the normal path and passes.
    function test_Batch_OnlyCancellationShapedEntryPasses() public {
        uint256 n = safe.nonce();
        assertTrue(
            _execSigned(
                infra.multiSendCallOnly,
                0,
                BatchEncoding.wrap(BatchEncoding.call(address(safe), 0, "")),
                Enum.Operation.DelegateCall
            )
        );
        assertEq(safe.nonce(), n + 1);
    }
}

contract BatchPolicyUnitTest is BatchPolicyTest, LocalSafe {
    function setUp() public override(BatchPolicyTest, FirewallTestBase) {
        BatchPolicyTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract BatchPolicyForkTest is BatchPolicyTest, FeatureForkSafe {
    function setUp() public override(BatchPolicyTest, FirewallTestBase) {
        BatchPolicyTest.setUp();
    }
}
