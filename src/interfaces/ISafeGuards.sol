// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Enum} from "./Enum.sol";
import {IERC165} from "./IERC165.sol";

// The Safe v1.5.0 guard hooks. The Safe only accepts a guard whose `supportsInterface` returns true
// for these interface ids (GuardManager.sol:72, ModuleManager.sol:259), so every signature here must
// match the Safe's exactly. test/unit/InterfaceIds.t.sol fails if either id drifts.

/// @title ITransactionGuard
/// @notice Hooks around `Safe.execTransaction` (lib/safe-smart-account/contracts/base/GuardManager.sol:13-50).
///         Interface id 0xe6d7a83a.
interface ITransactionGuard is IERC165 {
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external;

    function checkAfterExecution(bytes32 hash, bool success) external;
}

/// @title IModuleGuard
/// @notice Hooks around `execTransactionFromModule*` (lib/safe-smart-account/contracts/base/ModuleManager.sol:13-39).
///         Interface id 0x58401ed8.
interface IModuleGuard is IERC165 {
    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        address module
    ) external returns (bytes32 moduleTxHash);

    function checkAfterModuleExecution(bytes32 txHash, bool success) external;
}
