// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {IFallbackManager} from "safe-smart-account/contracts/interfaces/IFallbackManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";
import {MultiSendCallOnly} from "safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";

/// @notice I2.7-I2.11: the delegatecall policy on both paths (ADR 0003; spec pipeline step 2).
abstract contract DelegatecallPolicyTest is FirewallTestBase {
    address internal recipient;

    function setUp() public virtual override {
        super.setUp();
        recipient = _eoa("recipient");
    }

    /// @dev One packed MultiSend entry: operation (1 byte), to (20), value (32), data length (32),
    ///      data (lib/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol:13-18).
    function _batchOf(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodeCall(
            MultiSendCallOnly.multiSend, (abi.encodePacked(uint8(0), to, value, uint256(data.length), data))
        );
    }

    // ---------------------------------------------------------------- I2.7 signed: only MultiSendCallOnly

    function testFuzz_Delegatecall_SignedNonAllowlistedTargetReverts(address to) public {
        vm.assume(to != infra.multiSendCallOnly && to != address(guard));
        _execSignedExpectRevert(
            to,
            0,
            "",
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(ISafeFirewallGuard.DelegateCallNotAllowed.selector, to)
        );
    }

    function test_Delegatecall_SignedToSafeItselfReverts() public {
        _execSignedExpectRevert(
            address(safe),
            0,
            "",
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(ISafeFirewallGuard.DelegateCallNotAllowed.selector, address(safe))
        );
    }

    // ---------------------------------------------------------------- I2.8 MultiSendCallOnly passes (interim)

    /// @dev Passes the pre-check in Phase 2. The inner call is not decoded until Phase 3.
    function test_Delegatecall_SignedToMultiSendCallOnlyPasses() public {
        assertTrue(_execSigned(infra.multiSendCallOnly, 0, _batchOf(recipient, 1 wei, ""), Enum.Operation.DelegateCall));
        assertEq(recipient.balance, 1 wei);
    }

    /// @dev An inner self-call (setFallbackHandler) is still caught only by the post-check
    ///      (ProtectedStateChanged). Phase 3 decodes batches, but the pre-check has no self-call rule until
    ///      Phase 5. It flips to a pre-check rejection then, and this expectation is updated. (The ADR 0018
    ///      batch gap, an inner call to GUARD, flipped in Phase 3: see BatchPolicy.t.sol.)
    function test_Delegatecall_InterimBatchInnerCallCaughtOnlyByPostCheck() public {
        address newHandler = _eoa("newHandler");
        bytes memory inner = abi.encodeCall(IFallbackManager.setFallbackHandler, (newHandler));
        _execSignedExpectRevert(
            infra.multiSendCallOnly,
            0,
            _batchOf(address(safe), 0, inner),
            Enum.Operation.DelegateCall,
            _changed(ISafeFirewallGuard.ProtectedField.FALLBACK_HANDLER, _b32(infra.fallbackHandler), _b32(newHandler))
        );
    }

    // ---------------------------------------------------------------- I2.9 plain MultiSend rejected

    function test_Delegatecall_SignedPlainMultiSendReverts() public {
        _execSignedExpectRevert(
            infra.multiSend,
            0,
            _batchOf(recipient, 1 wei, ""),
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(ISafeFirewallGuard.DelegateCallNotAllowed.selector, infra.multiSend)
        );
    }

    // ---------------------------------------------------------------- I2.10 module path: never

    /// @dev Module pre-hook reverts propagate (ModuleManager.sol:107).
    function testFuzz_Delegatecall_ModuleAnyTargetReverts(address to) public {
        vm.assume(to != address(guard));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.ModuleDelegateCallNotAllowed.selector, to));
        module.exec(safe, to, 0, "", Enum.Operation.DelegateCall);
    }

    function test_Delegatecall_ModuleToMultiSendCallOnlyReverts() public {
        bytes memory batch = _batchOf(recipient, 1 wei, "");
        vm.expectRevert(
            abi.encodeWithSelector(ISafeFirewallGuard.ModuleDelegateCallNotAllowed.selector, infra.multiSendCallOnly)
        );
        module.exec(safe, infra.multiSendCallOnly, 0, batch, Enum.Operation.DelegateCall);
    }

    // ---------------------------------------------------------------- I2.11 regression: Call unaffected

    function test_Delegatecall_SignedCallUnaffected() public {
        assertTrue(_execSigned(recipient, 1 wei, "", Enum.Operation.Call));
        assertEq(recipient.balance, 1 wei);
    }

    function test_Delegatecall_ModuleCallUnaffected() public {
        assertTrue(module.exec(safe, recipient, 1 wei, "", Enum.Operation.Call));
        assertEq(recipient.balance, 1 wei);
    }
}

contract DelegatecallPolicyUnitTest is DelegatecallPolicyTest, LocalSafe {
    function setUp() public override(DelegatecallPolicyTest, FirewallTestBase) {
        DelegatecallPolicyTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract DelegatecallPolicyForkTest is DelegatecallPolicyTest, FeatureForkSafe {
    function setUp() public override(DelegatecallPolicyTest, FirewallTestBase) {
        DelegatecallPolicyTest.setUp();
    }
}
