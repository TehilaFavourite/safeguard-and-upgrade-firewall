// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {ISafe} from "safe-smart-account/contracts/interfaces/ISafe.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

/// @notice Minimal enabled module: forwards whatever it is told to execute through the module path.
contract TestModule {
    function exec(ISafe safe, address to, uint256 value, bytes calldata data, Enum.Operation op)
        external
        returns (bool success)
    {
        return safe.execTransactionFromModule(to, value, data, op);
    }

    function execReturnData(ISafe safe, address to, uint256 value, bytes calldata data, Enum.Operation op)
        external
        returns (bool success, bytes memory returnData)
    {
        return safe.execTransactionFromModuleReturnData(to, value, data, op);
    }
}
