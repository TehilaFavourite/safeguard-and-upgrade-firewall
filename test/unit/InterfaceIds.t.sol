// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {ITransactionGuard as SafeTransactionGuard} from "safe-smart-account/contracts/base/GuardManager.sol";
import {IModuleGuard as SafeModuleGuard} from "safe-smart-account/contracts/base/ModuleManager.sol";
import {IERC165 as SafeERC165} from "safe-smart-account/contracts/interfaces/IERC165.sol";
import {IGuardManager as SafeGuardManager} from "safe-smart-account/contracts/interfaces/IGuardManager.sol";
import {IModuleManager as SafeModuleManager} from "safe-smart-account/contracts/interfaces/IModuleManager.sol";
import {IOwnerManager as SafeOwnerManager} from "safe-smart-account/contracts/interfaces/IOwnerManager.sol";
import {
    IStorageAccessible as SafeStorageAccessible
} from "safe-smart-account/contracts/interfaces/IStorageAccessible.sol";
import {Enum as SafeEnum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ITransactionGuard, IModuleGuard} from "../../src/interfaces/ISafeGuards.sol";
import {IERC165} from "../../src/interfaces/IERC165.sol";
import {ISafe} from "../../src/interfaces/ISafe.sol";
import {Enum} from "../../src/interfaces/Enum.sol";

/// @notice src/ declares its own copies of the Safe v1.5.0 interfaces it uses. The Safe accepts the
///         guard only if `supportsInterface` returns true for its ids (GuardManager.sol:72,
///         ModuleManager.sol:259), and the escape path matches on the Safe's selectors (ADR 0014).
///         Any drift from the installed Safe source fails here.
contract InterfaceIdsTest is Test {
    function test_InterfaceIds_TransactionGuardMatchesSafe() public pure {
        assertEq(type(ITransactionGuard).interfaceId, type(SafeTransactionGuard).interfaceId);
    }

    function test_InterfaceIds_ModuleGuardMatchesSafe() public pure {
        assertEq(type(IModuleGuard).interfaceId, type(SafeModuleGuard).interfaceId);
    }

    function test_InterfaceIds_ERC165MatchesSafe() public pure {
        assertEq(type(IERC165).interfaceId, type(SafeERC165).interfaceId);
    }

    function test_InterfaceIds_HookSelectorsMatchSafe() public pure {
        assertEq(ITransactionGuard.checkTransaction.selector, SafeTransactionGuard.checkTransaction.selector);
        assertEq(ITransactionGuard.checkAfterExecution.selector, SafeTransactionGuard.checkAfterExecution.selector);
        assertEq(IModuleGuard.checkModuleTransaction.selector, SafeModuleGuard.checkModuleTransaction.selector);
        assertEq(IModuleGuard.checkAfterModuleExecution.selector, SafeModuleGuard.checkAfterModuleExecution.selector);
    }

    function test_InterfaceIds_SafeSelectorsMatchSafe() public pure {
        assertEq(ISafe.getStorageAt.selector, SafeStorageAccessible.getStorageAt.selector);
        assertEq(ISafe.getModulesPaginated.selector, SafeModuleManager.getModulesPaginated.selector);
        assertEq(ISafe.getOwners.selector, SafeOwnerManager.getOwners.selector);
        assertEq(ISafe.getThreshold.selector, SafeOwnerManager.getThreshold.selector);
        assertEq(ISafe.setGuard.selector, SafeGuardManager.setGuard.selector);
        assertEq(ISafe.setModuleGuard.selector, SafeModuleManager.setModuleGuard.selector);
    }

    function test_InterfaceIds_OperationValuesMatchSafe() public pure {
        assertEq(uint8(Enum.Operation.Call), uint8(SafeEnum.Operation.Call));
        assertEq(uint8(Enum.Operation.DelegateCall), uint8(SafeEnum.Operation.DelegateCall));
        assertEq(uint8(type(Enum.Operation).max), uint8(type(SafeEnum.Operation).max));
    }
}
