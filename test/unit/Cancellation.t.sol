// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {IFallbackManager} from "safe-smart-account/contracts/interfaces/IFallbackManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";
import {SafeFirewallGuardHarness} from "../harness/SafeFirewallGuardHarness.sol";
import {PolicyAlwaysRevertsGuard} from "../harness/SeamGuards.sol";
import {SequenceExecutor} from "../mocks/SequenceExecutor.sol";

/// @notice I2.4 and D2: the exact cancellation (threat model R2) always passes, uses up the nonce,
///         and its "skip the comparison" marker lives only for that execution (ADR 0020).
abstract contract CancellationTest is FirewallTestBase {
    function _cancellation() internal view returns (SafeTx memory) {
        return _safeTx(address(safe), 0, "", Enum.Operation.Call);
    }

    function test_Cancellation_PassesAndConsumesNonce() public {
        uint256 n = safe.nonce();
        assertTrue(_execTx(_cancellation()));
        assertEq(safe.nonce(), n + 1);
    }

    /// @dev Runbook procedure: a blocked transaction stays signed until its nonce is used. After the
    ///      cancellation, its signatures no longer match the hash for the new nonce. Safe recovers a
    ///      non-owner and reverts with GS026 (Safe.sol:338-339).
    function test_Cancellation_KillsBlockedSignedTx() public {
        address target = makeAddr("anyDelegatecallTarget");
        uint256 n = safe.nonce();
        bytes memory blockedSigs = _sign(_txHash(target, 0, "", Enum.Operation.DelegateCall, 0, n));

        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.DelegateCallNotAllowed.selector, target));
        safe.execTransaction(
            target, 0, "", Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), blockedSigs
        );
        assertEq(safe.nonce(), n, "blocked tx must not use up the nonce");

        assertTrue(_execTx(_cancellation()));

        vm.expectRevert(bytes("GS026"));
        safe.execTransaction(
            target, 0, "", Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), blockedSigs
        );
    }

    /// @dev D2: the marker exists only for the cancellation's own execution. A protected change in the
    ///      next execution of the same Ethereum transaction is still compared and reverts.
    function test_Cancellation_MarkerDoesNotLeakToNextExecution() public {
        SequenceExecutor sequencer = new SequenceExecutor();
        address oldHandler = infra.fallbackHandler;
        address newHandler = makeAddr("newHandler");
        uint256 n = safe.nonce();

        SequenceExecutor.Step[] memory steps = new SequenceExecutor.Step[](2);
        steps[0] =
            SequenceExecutor.Step(address(safe), _signedExecCalldata(address(safe), 0, "", Enum.Operation.Call, 0, n));
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

        assertTrue(ok[0], "cancellation must pass");
        assertFalse(ok[1], "protected change after a cancellation must still be compared");
        assertEq(
            ret[1], _changed(ISafeFirewallGuard.ProtectedField.FALLBACK_HANDLER, _b32(oldHandler), _b32(newHandler))
        );
    }
}

/// @notice I2.5: R2 doesn't depend on policy. Both seams always revert, and the cancellation still passes.
abstract contract CancellationHostileGuardTest is FirewallTestBase {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        virtual
        override
        returns (SafeFirewallGuardHarness)
    {
        return new PolicyAlwaysRevertsGuard(config);
    }

    function test_Cancellation_PassesWhenPolicyAlwaysReverts() public {
        uint256 n = safe.nonce();
        assertTrue(_execTx(_safeTx(address(safe), 0, "", Enum.Operation.Call)));
        assertEq(safe.nonce(), n + 1);
    }

    /// @dev Sanity check that the guard really is hostile: anything that isn't the exact cancellation
    ///      reverts.
    function test_HostileGuard_BlocksOrdinaryCall() public {
        _execTxExpectRevert(
            _safeTx(makeAddr("recipient"), 1 wei, "", Enum.Operation.Call),
            abi.encodeWithSelector(PolicyAlwaysRevertsGuard.SeamForcedRevert.selector)
        );
    }
}

contract CancellationUnitTest is CancellationTest, LocalSafe {}

/// forge-config: default.fuzz.runs = 64
contract CancellationForkTest is CancellationTest, FeatureForkSafe {}

contract CancellationHostileGuardUnitTest is CancellationHostileGuardTest, LocalSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(CancellationHostileGuardTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return CancellationHostileGuardTest._newGuard(config);
    }
}

/// forge-config: default.fuzz.runs = 64
contract CancellationHostileGuardForkTest is CancellationHostileGuardTest, FeatureForkSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(CancellationHostileGuardTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return CancellationHostileGuardTest._newGuard(config);
    }
}
