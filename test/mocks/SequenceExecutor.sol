// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Runs several calls inside one call frame, so they share one Ethereum transaction's
///         transient storage regardless of how the test runner isolates calls.
contract SequenceExecutor {
    struct Step {
        address target;
        bytes data;
    }

    function run(Step[] calldata steps) external returns (bool[] memory ok) {
        ok = new bool[](steps.length);
        for (uint256 i = 0; i < steps.length; i++) {
            (ok[i],) = steps[i].target.call(steps[i].data);
        }
    }
}
