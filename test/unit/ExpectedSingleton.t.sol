// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ITransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {Safe} from "safe-smart-account/contracts/Safe.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";

/// @notice I2.23: every pre-hook checks masterCopy() == expectedSingleton (ADR 0020). The comparison
///         only catches changes made during a transaction. This check catches a Safe that was
///         already wrong. Placement is after step 7 and before the snapshot, so cancellation (and,
///         from Phase 4, escape) still works on an already-compromised Safe.
abstract contract ExpectedSingletonTest is FirewallTestBase {
    // lib/safe-smart-account/contracts/libraries/SafeStorage.sol:11
    bytes32 internal constant SINGLETON_SLOT = bytes32(uint256(0));

    address internal otherSingleton;

    /// @dev A second, functionally identical Safe singleton at a different address, so the Safe keeps
    ///      working after the swap and only the identity check can tell.
    function setUp() public virtual override {
        super.setUp();
        otherSingleton = address(new Safe());
        vm.store(address(safe), SINGLETON_SLOT, bytes32(uint256(uint160(otherSingleton))));
    }

    function _unexpected() internal view returns (bytes memory) {
        return abi.encodeWithSelector(ISafeFirewallGuard.UnexpectedSingleton.selector, otherSingleton, infra.singleton);
    }

    function test_ExpectedSingleton_AlreadySwappedBlocksSignedTx() public {
        _execSignedExpectRevert(makeAddr("recipient"), 1 wei, "", Enum.Operation.Call, _unexpected());
    }

    function test_ExpectedSingleton_AlreadySwappedBlocksModuleTx() public {
        address recipient = makeAddr("recipient");
        vm.expectRevert(_unexpected());
        module.exec(safe, recipient, 1 wei, "", Enum.Operation.Call);
    }

    /// @dev Cancellation returns at step 6, before the identity check, so a compromised Safe can still
    ///      burn a nonce.
    function test_ExpectedSingleton_CancellationStillPasses() public {
        uint256 n = safe.nonce();
        assertTrue(_execTx(_safeTx(address(safe), 0, "", Enum.Operation.Call)));
        assertEq(safe.nonce(), n + 1);
    }

    /// @dev Order: step 7 (calls to GUARD) runs before the identity check (step 8).
    function test_ExpectedSingleton_GuardCallRejectedFirst() public {
        bytes memory data = abi.encodeCall(ITransactionGuard.checkAfterExecution, (bytes32(0), true));
        _execSignedExpectRevert(
            address(guard),
            0,
            data,
            Enum.Operation.Call,
            abi.encodeWithSelector(
                ISafeFirewallGuard.GuardCallRejected.selector, ITransactionGuard.checkAfterExecution.selector
            )
        );
    }

    /// @dev Control: with the correct singleton restored, the same transaction passes.
    function test_ExpectedSingleton_ControlCorrectSingletonPasses() public {
        vm.store(address(safe), SINGLETON_SLOT, bytes32(uint256(uint160(infra.singleton))));
        assertTrue(_execSigned(makeAddr("recipient"), 1 wei, "", Enum.Operation.Call));
    }
}

contract ExpectedSingletonUnitTest is ExpectedSingletonTest, LocalSafe {
    function setUp() public override(ExpectedSingletonTest, FirewallTestBase) {
        ExpectedSingletonTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract ExpectedSingletonForkTest is ExpectedSingletonTest, FeatureForkSafe {
    function setUp() public override(ExpectedSingletonTest, FirewallTestBase) {
        ExpectedSingletonTest.setUp();
    }
}
