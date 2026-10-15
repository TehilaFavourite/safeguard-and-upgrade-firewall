// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {MultiSendCallOnly} from "safe-smart-account/contracts/libraries/MultiSendCallOnly.sol";

/// @notice Builds MultiSend batches. One packed entry: operation (1 byte), to (20), value (32), data
///         length (32), data (lib/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol:13-18).
library BatchEncoding {
    uint256 internal constant HEADER = 85;
    /// @dev selector (4) + ABI offset word (32) + ABI length word (32)
    uint256 internal constant WRAPPER = 68;

    function entry(uint8 op, address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(op, to, value, uint256(data.length), data);
    }

    function call(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return entry(0, to, value, data);
    }

    /// @dev Canonical ABI encoding: offset 0x20, length word, zero padding to 32 bytes.
    function wrap(bytes memory packed) internal pure returns (bytes memory) {
        return abi.encodeCall(MultiSendCallOnly.multiSend, (packed));
    }
}
