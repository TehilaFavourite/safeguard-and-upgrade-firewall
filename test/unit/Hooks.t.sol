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

/// @notice I1.1 (caller check), I1.2 (ERC-165), I1.3 (Safe accepts the guard).
abstract contract HooksTest is FirewallTestBase {
    // Interface IDs as documented in the installed Safe source.
    bytes4 internal constant TRANSACTION_GUARD_ID = 0xe6d7a83a; // GuardManager.sol:55
    bytes4 internal constant MODULE_GUARD_ID = 0x58401ed8; // ModuleManager.sol:44
    bytes4 internal constant ERC165_ID = 0x01ffc9a7; // GuardManager.sol:56

    // ---------------------------------------------------------------- I1.1 caller check

    function testFuzz_Hooks_CheckTransactionRevertsForNonSafe(address caller) public {
        vm.assume(caller != address(safe));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, caller));
        vm.prank(caller);
        guard.checkTransaction(
            address(0), 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), "", address(0)
        );
    }

    function testFuzz_Hooks_CheckAfterExecutionRevertsForNonSafe(address caller) public {
        vm.assume(caller != address(safe));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, caller));
        vm.prank(caller);
        guard.checkAfterExecution(bytes32(0), true);
    }

    function testFuzz_Hooks_CheckModuleTransactionRevertsForNonSafe(address caller) public {
        vm.assume(caller != address(safe));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, caller));
        vm.prank(caller);
        guard.checkModuleTransaction(address(0), 0, "", Enum.Operation.Call, address(module));
    }

    function testFuzz_Hooks_CheckAfterModuleExecutionRevertsForNonSafe(address caller) public {
        vm.assume(caller != address(safe));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.NotSafe.selector, caller));
        vm.prank(caller);
        guard.checkAfterModuleExecution(bytes32(0), true);
    }

    // ---------------------------------------------------------------- I1.2 ERC-165

    function test_ERC165_SupportsTransactionGuard() public view {
        assertEq(type(ITransactionGuard).interfaceId, TRANSACTION_GUARD_ID, "interface id drifted from Safe source");
        assertTrue(guard.supportsInterface(TRANSACTION_GUARD_ID));
    }

    function test_ERC165_SupportsModuleGuard() public view {
        assertEq(type(IModuleGuard).interfaceId, MODULE_GUARD_ID, "interface id drifted from Safe source");
        assertTrue(guard.supportsInterface(MODULE_GUARD_ID));
    }

    function test_ERC165_SupportsIERC165() public view {
        assertEq(type(IERC165).interfaceId, ERC165_ID);
        assertTrue(guard.supportsInterface(ERC165_ID));
    }

    function test_ERC165_RejectsInvalidId() public view {
        assertFalse(guard.supportsInterface(0xffffffff));
    }

    function testFuzz_ERC165_RejectsOtherIds(bytes4 id) public view {
        vm.assume(id != TRANSACTION_GUARD_ID && id != MODULE_GUARD_ID && id != ERC165_ID);
        assertFalse(guard.supportsInterface(id));
    }

    // ---------------------------------------------------------------- I1.3 Safe accepts the guard

    /// @dev setUp installs the guard through setModuleGuard and setGuard. Either would revert with
    ///      GS301 / GS300 if the ERC-165 check failed (ModuleManager.sol:259-260, GuardManager.sol:72-73).
    function test_Install_SetGuardAndSetModuleGuardAccepted() public view {
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(guard), "transaction guard slot");
        assertEq(_readSlotAddress(MODULE_GUARD_STORAGE_SLOT), address(guard), "module guard slot");
    }
}

contract HooksUnitTest is HooksTest, LocalSafe {}

/// forge-config: default.fuzz.runs = 64
contract HooksForkTest is HooksTest, FeatureForkSafe {}
