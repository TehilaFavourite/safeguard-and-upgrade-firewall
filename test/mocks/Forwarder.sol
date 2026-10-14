// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Calls `target` with `data` and bubbles any revert unchanged. Used to re-enter the Safe
///         from inside a guarded execution.
contract Forwarder {
    function forward(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return ret;
    }
}
