// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

/// @notice Reverts on every call. Used to make a Safe inner call fail.
contract Reverter {
    error AlwaysReverts();

    fallback() external payable {
        revert AlwaysReverts();
    }
}
