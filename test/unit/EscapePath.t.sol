// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Safe} from "safe-smart-account/contracts/Safe.sol";
import {IFallbackManager} from "safe-smart-account/contracts/interfaces/IFallbackManager.sol";
import {IModuleManager} from "safe-smart-account/contracts/interfaces/IModuleManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {TimelockTestBase} from "../base/TimelockTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";
import {SafeFirewallGuardHarness} from "../harness/SafeFirewallGuardHarness.sol";
import {PolicyAlwaysRevertsGuard} from "../harness/SeamGuards.sol";
import {MutableBindingGuard, SafeRefusingGuard} from "../mocks/StateMutators.sol";
import {SequenceExecutor} from "../mocks/SequenceExecutor.sol";
import {BatchEncoding} from "../helpers/BatchEncoding.sol";

/// @notice I4.6-I4.13 and I4.20: the R1 escape path (ADR 0014, ADR 0023).
abstract contract EscapePathTest is TimelockTestBase {
    SafeFirewallGuardHarness internal next;

    function setUp() public virtual override {
        super.setUp();
        next = _replacement("nextGuardian");
    }

    function _queueNext() internal returns (bytes32) {
        return _queueEscape(address(next), address(next).codehash);
    }

    // ---------------------------------------------------------------- happy paths

    function test_Escape_QueueSetsEta72hAndPending() public {
        bytes32 id = _queueNext();
        ISafeFirewallGuard.Item memory item = guard.getItem(id);
        assertEq(uint8(item.kind), uint8(ISafeFirewallGuard.ItemKind.ESCAPE));
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(item.eta, uint64(block.timestamp + ESCAPE_DELAY)); // timestamps fit in uint64
        assertEq(guard.pendingEscape(address(next)), id);
    }

    function test_Escape_ReplacementSucceedsAfterDelay() public {
        bytes32 id = _queueNext();
        vm.warp(block.timestamp + ESCAPE_DELAY);
        assertTrue(_execSigned(address(safe), 0, _setModuleGuardData(address(next)), Enum.Operation.Call));
        // Sign first, so the expectation applies to execTransaction and not to nonce()/getTransactionHash().
        SafeTx memory t = _safeTx(address(safe), 0, _setGuardData(address(next)), Enum.Operation.Call);
        bytes memory sigs = _signTx(t);
        vm.expectEmit(true, true, false, false, address(guard));
        emit ISafeFirewallGuard.Executed(id, ISafeFirewallGuard.ItemKind.ESCAPE);
        safe.execTransaction(t.to, 0, t.data, t.operation, 0, 0, 0, address(0), payable(address(0)), sigs);
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(next));
        assertEq(_readSlotAddress(MODULE_GUARD_STORAGE_SLOT), address(next));
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.EXECUTED));
    }

    function test_Escape_RemovalSucceedsAfterDelay() public {
        _queueEscape(address(0), bytes32(0));
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _executeEscape(address(0));
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(0));
        assertEq(_readSlotAddress(MODULE_GUARD_STORAGE_SLOT), address(0));
    }

    /// @dev A replacement deployed by a third party through the permissionless factory is accepted:
    ///      the item binds address and codehash, not who deployed it (ADR 0007, ADR 0014).
    function test_Escape_ReplacementDeployedByThirdPartyAccepted() public {
        // `next` was deployed by this test contract, not by the Safe: same property.
        _queueNext();
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _executeEscape(address(next));
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(next));
    }

    // ---------------------------------------------------------------- I4.3 maturity and expiry on the escape path

    function test_Escape_BeforeDelayReverts() public {
        bytes32 id = _queueNext();
        vm.warp(block.timestamp + ESCAPE_DELAY - 1);
        _execSignedExpectRevert(
            address(safe),
            0,
            _setModuleGuardData(address(next)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.NotMatured.selector, id, guard.getItem(id).eta)
        );
    }

    function test_Escape_AfterExpiryReverts() public {
        bytes32 id = _queueNext();
        uint64 expiresAt = guard.getItem(id).expiresAt;
        vm.warp(expiresAt);
        _execSignedExpectRevert(
            address(safe),
            0,
            _setModuleGuardData(address(next)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.ItemExpired.selector, id, expiresAt)
        );
    }

    /// @dev D4: marking an escape item expired frees its target. A setModuleGuard(x) with no pending
    ///      item is not an escape, so it takes the normal pipeline and the post-check rejects it.
    function test_Escape_MarkExpiredClearsPendingTarget() public {
        bytes32 id = _queueNext();
        vm.warp(guard.getItem(id).expiresAt);
        guard.markExpired(id);
        assertEq(guard.pendingEscape(address(next)), bytes32(0));
        _execSignedExpectRevert(
            address(safe),
            0,
            _setModuleGuardData(address(next)),
            Enum.Operation.Call,
            _changed(ISafeFirewallGuard.ProtectedField.MODULE_GUARD, _b32(address(guard)), _b32(address(next)))
        );
        bytes32 again = _queueNext();
        assertEq(guard.pendingEscape(address(next)), again);
    }

    /// @dev Removal binds no code: the only accepted codehash for target 0 is 0.
    function test_Escape_RemovalWithCodehashRejected() public {
        bytes32 c = keccak256("anything");
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(0), c)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.EscapeCodehashMismatch.selector, address(0), c, bytes32(0))
        );
    }

    function test_CancelEscape_WrongKindRejected() public {
        bytes32 id = guard.exposedQueue(ISafeFirewallGuard.ItemKind.CONFIG, keccak256("cap:token"), hex"01");
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.cancelEscape, (id)),
            Enum.Operation.Call,
            abi.encodeWithSelector(
                ISafeFirewallGuard.WrongItemKind.selector,
                id,
                ISafeFirewallGuard.ItemKind.ESCAPE,
                ISafeFirewallGuard.ItemKind.CONFIG
            )
        );
    }

    /// @dev R1 accepts one encoding only: an address argument with dirty high bits is not an escape,
    ///      even when its low 160 bits name a matured target. What the Safe then does depends on its
    ///      ABI decoder. The canonical v1.5.0 singleton (solc 0.7.6, ABI coder v1; hardhat.config.ts:53)
    ///      truncates the argument and sets the module guard, so the post-check rejects it (fork
    ///      variant). The local build (solc 0.8.28, ABI coder v2) rejects the word and Safe.sol:184-190
    ///      bubbles the empty revert up (unit variant). Without the clean-bits check in R1, the fork
    ///      variant would install the guard on the fast path.
    function test_Escape_DirtyAddressArgumentGetsNoFastPath() public {
        _queueNext();
        vm.warp(block.timestamp + ESCAPE_DELAY);
        bytes memory data =
            abi.encodePacked(IModuleManager.setModuleGuard.selector, (uint256(1) << 160) | uint160(address(next)));
        bytes memory sigs = _sign(_txHash(address(safe), 0, data, Enum.Operation.Call, 0, safe.nonce()));
        (bool ok, bytes memory ret) = address(safe)
            .call(
                abi.encodeCall(
                    Safe.execTransaction,
                    (address(safe), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sigs)
                )
            );
        assertFalse(ok, "dirty-argument setModuleGuard must not succeed");
        bytes memory postCheck =
            _changed(ISafeFirewallGuard.ProtectedField.MODULE_GUARD, _b32(address(guard)), _b32(address(next)));
        assertTrue(ret.length == 0 || keccak256(ret) == keccak256(postCheck), "unexpected revert data");
        assertEq(_readSlotAddress(MODULE_GUARD_STORAGE_SLOT), address(guard));
    }

    function test_Escape_OnePendingPerTarget() public {
        bytes32 id = _queueNext();
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(next), address(next).codehash)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.EscapeAlreadyPending.selector, address(next), id)
        );
    }

    // ---------------------------------------------------------------- I4.7 codehash binding

    function test_Escape_CodehashMismatchAtQueueReverts() public {
        bytes32 wrong = keccak256("not the code");
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(next), wrong)),
            Enum.Operation.Call,
            abi.encodeWithSelector(
                ISafeFirewallGuard.EscapeCodehashMismatch.selector, address(next), wrong, address(next).codehash
            )
        );
    }

    /// @dev The code at the target changes between queue and execute (simulated with vm.etch).
    function test_Escape_CodehashChangedBeforeExecuteReverts() public {
        bytes32 bound = address(next).codehash;
        _queueNext();
        vm.etch(address(next), address(new MutableBindingGuard(address(safe))).code);
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _execSignedExpectRevert(
            address(safe),
            0,
            _setModuleGuardData(address(next)),
            Enum.Operation.Call,
            abi.encodeWithSelector(
                ISafeFirewallGuard.EscapeCodehashMismatch.selector, address(next), bound, address(next).codehash
            )
        );
    }

    // ---------------------------------------------------------------- I4.8 enforced order

    function test_Escape_SetGuardBeforeModuleGuardReverts() public {
        _queueNext();
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _execSignedExpectRevert(
            address(safe),
            0,
            _setGuardData(address(next)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.EscapeOrderViolation.selector, address(next), address(guard))
        );
    }

    // ---------------------------------------------------------------- I4.6 near-miss shapes get no fast path

    function test_Escape_QueueInsideBatchRejected() public {
        bytes memory q = abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(next), address(next).codehash));
        _execSignedExpectRevert(
            infra.multiSendCallOnly,
            0,
            BatchEncoding.wrap(BatchEncoding.call(address(guard), 0, q)),
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardCallRejected.selector, ISafeFirewallGuard.queueEscape.selector
            )
        );
    }

    function test_Escape_QueueAsDelegatecallRejected() public {
        bytes memory q = abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(next), address(next).codehash));
        _execSignedExpectRevert(
            address(guard),
            0,
            q,
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardCallRejected.selector, ISafeFirewallGuard.queueEscape.selector
            )
        );
    }

    function test_Escape_QueueWithValueRejected() public {
        bytes memory q = abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(next), address(next).codehash));
        _execSignedExpectRevert(
            address(guard),
            1,
            q,
            Enum.Operation.Call,
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardCallRejected.selector, ISafeFirewallGuard.queueEscape.selector
            )
        );
    }

    function test_Escape_QueueWithRefundFieldRejected() public {
        SafeTx memory t = _safeTx(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(next), address(next).codehash)),
            Enum.Operation.Call
        );
        t.gasPrice = 1;
        _execTxExpectRevert(
            t, abi.encodeWithSelector(ISafeFirewallGuard.RefundNotAllowed.selector, 1, address(0), address(0))
        );
    }

    // ---------------------------------------------------------------- I4.10 marker doesn't leak

    function test_Escape_FastReturnMarkerDoesNotLeak() public {
        _queueNext();
        vm.warp(block.timestamp + ESCAPE_DELAY);
        SequenceExecutor sequencer = new SequenceExecutor();
        address newHandler = _eoa("newHandler");
        uint256 n = safe.nonce();
        SequenceExecutor.Step[] memory steps = new SequenceExecutor.Step[](2);
        steps[0] = SequenceExecutor.Step(
            address(safe),
            _signedExecCalldata(address(safe), 0, _setModuleGuardData(address(next)), Enum.Operation.Call, 0, n)
        );
        steps[1] = SequenceExecutor.Step(
            address(safe),
            _signedExecCalldata(
                address(safe),
                0,
                abi.encodeCall(IFallbackManager.setFallbackHandler, (newHandler)),
                Enum.Operation.Call,
                0,
                n + 1
            )
        );
        (bool[] memory ok, bytes[] memory ret) = sequencer.run(steps);
        assertTrue(ok[0], "escape step must pass");
        assertFalse(ok[1], "the next execution must still be compared");
        // The second execution's pre-check runs on the guard that is still the transaction guard.
        assertEq(
            ret[1],
            _changed(ISafeFirewallGuard.ProtectedField.FALLBACK_HANDLER, _b32(infra.fallbackHandler), _b32(newHandler))
        );
    }

    // ---------------------------------------------------------------- I4.11 consumed only on success (D7)

    /// @dev The inner setGuard reverts (the target refuses the Safe's interface query), so
    ///      execTransaction returns success == false. safeTxGas must be non-zero, or the Safe reverts
    ///      GS013 instead (Safe.sol:184). A small safeTxGas can't force the failure: with gasPrice 0
    ///      (required by the refund ban) the Safe forwards gasleft() - 2500 regardless (Safe.sol:180).
    function test_Escape_NotConsumedWhenSetGuardFails() public {
        SafeRefusingGuard x = new SafeRefusingGuard(address(safe));
        bytes32 id = _queueEscape(address(x), address(x).codehash);
        vm.warp(block.timestamp + ESCAPE_DELAY);
        assertTrue(_execSigned(address(safe), 0, _setModuleGuardData(address(x)), Enum.Operation.Call));

        x.setRefuseSafe(true);
        SafeTx memory t = _safeTx(address(safe), 0, _setGuardData(address(x)), Enum.Operation.Call);
        t.safeTxGas = 100_000;
        assertFalse(_execTx(t), "inner setGuard should have failed");
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(guard), "setGuard should have failed");
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.QUEUED), "item burned by a failed execution");
        assertEq(guard.pendingEscape(address(x)), id);

        x.setRefuseSafe(false);
        assertTrue(_execSigned(address(safe), 0, _setGuardData(address(x)), Enum.Operation.Call), "retry");
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(x));
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.EXECUTED));
    }

    // ---------------------------------------------------------------- I4.12 module path

    function test_Escape_ModulePathCannotQueue() public {
        bytes memory q = abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(next), address(next).codehash));
        vm.expectRevert(
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardCallRejected.selector, ISafeFirewallGuard.queueEscape.selector
            )
        );
        module.exec(safe, address(guard), 0, q, Enum.Operation.Call);
    }

    /// @dev Even with a matured item, the module path gets no fast path: the post-check catches it.
    function test_Escape_ModulePathCannotExecuteMaturedItem() public {
        _queueNext();
        vm.warp(block.timestamp + ESCAPE_DELAY);
        vm.expectRevert(
            _changed(ISafeFirewallGuard.ProtectedField.MODULE_GUARD, _b32(address(guard)), _b32(address(next)))
        );
        module.exec(safe, address(safe), 0, _setModuleGuardData(address(next)), Enum.Operation.Call);
    }

    // ---------------------------------------------------------------- I4.13 escape-shaped batch entries

    function test_Escape_ShapedInnerBatchEntryGetsNoFastPath() public {
        _queueNext();
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _execSignedExpectRevert(
            infra.multiSendCallOnly,
            0,
            BatchEncoding.wrap(BatchEncoding.call(address(safe), 0, _setModuleGuardData(address(next)))),
            Enum.Operation.DelegateCall,
            _changed(ISafeFirewallGuard.ProtectedField.MODULE_GUARD, _b32(address(guard)), _b32(address(next)))
        );
    }

    // ---------------------------------------------------------------- I4.16 signers cancel escape (R1)

    function test_Escape_SignersCancelEscape() public {
        bytes32 id = _queueNext();
        vm.expectEmit(true, true, true, false, address(guard));
        emit ISafeFirewallGuard.Cancelled(id, ISafeFirewallGuard.ItemKind.ESCAPE, address(safe));
        assertTrue(
            _execSigned(address(guard), 0, abi.encodeCall(ISafeFirewallGuard.cancelEscape, (id)), Enum.Operation.Call)
        );
        assertEq(guard.pendingEscape(address(next)), bytes32(0));
    }

    function test_Escape_CancelRequiresCancelEscape() public {
        bytes32 id = _queueNext();
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.cancel, (id)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.EscapeRequiresCancelEscape.selector, id)
        );
    }

    // ---------------------------------------------------------------- I4.20 escape target bound to this Safe

    function test_Escape_TargetBoundToOtherSafeRejectedAtQueue() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        address otherSafe = _eoa("otherSafe");
        cfg.safe = otherSafe;
        address foreign = address(new SafeFirewallGuardHarness(cfg));
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueEscape, (foreign, foreign.codehash)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.EscapeTargetNotBound.selector, foreign, otherSafe)
        );
    }

    function test_Escape_TargetWithoutGuardInterfacesRejectedAtQueue() public {
        MutableBindingGuard target = new MutableBindingGuard(address(safe));
        target.setSupportsBoth(false);
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(target), address(target).codehash)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.EscapeTargetNotBound.selector, address(target), address(safe))
        );
    }

    /// @dev A target with no code: the SAFE() read fails and is reported as address(0).
    function test_Escape_TargetWithoutCodeRejectedAtQueue() public {
        address eoa = _eoa("notAGuard");
        _execSignedExpectRevert(
            address(guard),
            0,
            abi.encodeCall(ISafeFirewallGuard.queueEscape, (eoa, eoa.codehash)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.EscapeTargetNotBound.selector, eoa, address(0))
        );
    }

    /// @dev Same code (same codehash), different answer: the execute-time re-check catches it.
    function test_Escape_TargetStopsMatchingRejectedAtExecute() public {
        MutableBindingGuard target = new MutableBindingGuard(address(safe));
        _queueEscape(address(target), address(target).codehash);
        address otherSafe = _eoa("otherSafe");
        target.setSafe(otherSafe);
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _execSignedExpectRevert(
            address(safe),
            0,
            _setModuleGuardData(address(target)),
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.EscapeTargetNotBound.selector, address(target), otherSafe)
        );
    }

    /// @dev The documented exception: a replacement with a WRONG expectedSingleton is NOT rejected. Once
    ///      installed its ordinary transactions fail closed (UnexpectedSingleton), but its own cancellation
    ///      and escape still work, because they run before its step-8 check. So it is recoverable.
    function test_Escape_WrongExpectedSingletonReplacementIsRecoverable() public {
        ISafeFirewallGuard.FirewallConfig memory cfg = _config();
        cfg.guardian = _eoa("wrongSingletonGuardian");
        cfg.singleton = address(new Safe());
        SafeFirewallGuardHarness wrong = new SafeFirewallGuardHarness(cfg);

        _queueEscape(address(wrong), address(wrong).codehash);
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _executeEscape(address(wrong));

        _execSignedExpectRevert(
            _eoa("recipient"),
            1 wei,
            "",
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.UnexpectedSingleton.selector, infra.singleton, cfg.singleton)
        );
        assertTrue(_execTx(_safeTx(address(safe), 0, "", Enum.Operation.Call)), "cancellation must still pass");

        // Recover: the wrong guard's own escape removes it.
        assertTrue(
            _execSigned(
                address(wrong),
                0,
                abi.encodeCall(ISafeFirewallGuard.queueEscape, (address(0), bytes32(0))),
                Enum.Operation.Call
            )
        );
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _executeEscape(address(0));
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(0), "recovered");
    }
}

/// @notice I4.9: R1 doesn't depend on policy. Both seams always revert, and queueing, executing and
///         cancelling an escape still work.
abstract contract EscapeHostileGuardTest is TimelockTestBase {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        virtual
        override
        returns (SafeFirewallGuardHarness)
    {
        return new PolicyAlwaysRevertsGuard(config);
    }

    function test_Escape_WorksWhenPolicyAlwaysReverts() public {
        SafeFirewallGuardHarness next = _replacement("nextGuardian");
        _queueEscape(address(next), address(next).codehash);
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _executeEscape(address(next));
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(next));
    }

    function test_Escape_CancelWorksWhenPolicyAlwaysReverts() public {
        bytes32 id = _queueEscape(address(0), bytes32(0));
        assertTrue(
            _execSigned(address(guard), 0, abi.encodeCall(ISafeFirewallGuard.cancelEscape, (id)), Enum.Operation.Call)
        );
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.CANCELLED));
    }
}

/// @notice I4.9: R1 runs before the module read and the expected-singleton check.
abstract contract EscapeCompromisedStateTest is TimelockTestBase {
    // lib/safe-smart-account/contracts/libraries/SafeStorage.sol:11
    bytes32 internal constant SINGLETON_SLOT = bytes32(uint256(0));
    uint256 internal constant MAX_MODULES = 16;

    function _beforeGuardInstall() internal virtual override {
        for (uint256 i = 1; i <= MAX_MODULES; i++) {
            _execSigned(
                address(safe),
                0,
                // forge-lint: disable-next-line(unsafe-typecast)
                abi.encodeCall(IModuleManager.enableModule, (address(uint160(0x20000 + i)))), // i <= 16: no truncation
                Enum.Operation.Call
            );
        }
    }

    /// @dev Over the module limit AND on an unexpected (but working) singleton: removal still works.
    function test_Escape_WorksOverModuleLimitAndWithUnexpectedSingleton() public {
        bytes32 id = _queueEscape(address(0), bytes32(0));
        vm.store(address(safe), SINGLETON_SLOT, bytes32(uint256(uint160(address(new Safe())))));
        vm.warp(block.timestamp + ESCAPE_DELAY);
        _executeEscape(address(0));
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(0));
        assertEq(uint8(_status(id)), uint8(ISafeFirewallGuard.ItemStatus.EXECUTED));
    }
}

contract EscapePathUnitTest is EscapePathTest, LocalSafe {
    function setUp() public override(EscapePathTest, FirewallTestBase) {
        EscapePathTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract EscapePathForkTest is EscapePathTest, FeatureForkSafe {
    function setUp() public override(EscapePathTest, FirewallTestBase) {
        EscapePathTest.setUp();
    }
}

contract EscapeHostileGuardUnitTest is EscapeHostileGuardTest, LocalSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(EscapeHostileGuardTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return EscapeHostileGuardTest._newGuard(config);
    }
}

/// forge-config: default.fuzz.runs = 64
contract EscapeHostileGuardForkTest is EscapeHostileGuardTest, FeatureForkSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(EscapeHostileGuardTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return EscapeHostileGuardTest._newGuard(config);
    }
}

contract EscapeCompromisedStateUnitTest is EscapeCompromisedStateTest, LocalSafe {
    function _beforeGuardInstall() internal override(EscapeCompromisedStateTest, FirewallTestBase) {
        EscapeCompromisedStateTest._beforeGuardInstall();
    }
}

/// forge-config: default.fuzz.runs = 64
contract EscapeCompromisedStateForkTest is EscapeCompromisedStateTest, FeatureForkSafe {
    function _beforeGuardInstall() internal override(EscapeCompromisedStateTest, FirewallTestBase) {
        EscapeCompromisedStateTest._beforeGuardInstall();
    }
}
