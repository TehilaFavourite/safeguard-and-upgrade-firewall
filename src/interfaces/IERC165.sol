// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IERC165
/// @notice EIP-165 interface detection. Interface id 0x01ffc9a7.
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
