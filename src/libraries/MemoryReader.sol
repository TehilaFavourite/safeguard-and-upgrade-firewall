// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @title MemoryReader
/// @notice Read-only, bounds-checked field reads from `bytes memory` at an offset (ADR 0005, second
///         assembly exception; docs/engineering-principles.md).
/// @dev Exactly one `mload` per read, in `_load`, and no `mstore` anywhere. Every read checks its
///      bounds first, without overflow: `offset > length || size > length - offset` never adds, so an
///      offset near type(uint256).max reverts with `MemoryReadOutOfBounds` instead of wrapping.
///      `mload` always loads 32 bytes. A field shorter than 32 bytes that ends at the last byte of the
///      buffer therefore also loads up to 31 bytes past the end. Each reader shifts or truncates those
///      bytes away, keeping only the field's own high-order bytes.
library MemoryReader {
    /// @notice A read of `size` bytes at `offset` would run past `length`.
    error MemoryReadOutOfBounds(uint256 offset, uint256 size, uint256 length);

    uint256 private constant UINT8_SIZE = 1;
    uint256 private constant BYTES4_SIZE = 4;
    uint256 private constant ADDRESS_SIZE = 20;
    uint256 private constant WORD_SIZE = 32;
    /// @dev 256 - 8: keep the top byte.
    uint256 private constant UINT8_SHIFT = 248;
    /// @dev 256 - 160: keep the top 20 bytes.
    uint256 private constant ADDRESS_SHIFT = 96;

    /// @notice The byte at `offset`.
    function readUint8(bytes memory b, uint256 offset) internal pure returns (uint8) {
        return uint8(uint256(_load(b, offset, UINT8_SIZE)) >> UINT8_SHIFT);
    }

    /// @notice The 4 bytes at `offset`, for example a selector.
    function readBytes4(bytes memory b, uint256 offset) internal pure returns (bytes4) {
        return bytes4(_load(b, offset, BYTES4_SIZE));
    }

    /// @notice The 20 bytes at `offset`, as an address.
    function readAddress(bytes memory b, uint256 offset) internal pure returns (address) {
        return address(uint160(uint256(_load(b, offset, ADDRESS_SIZE)) >> ADDRESS_SHIFT));
    }

    /// @notice The 32 bytes at `offset`, as a big-endian uint256.
    function readUint256(bytes memory b, uint256 offset) internal pure returns (uint256) {
        return uint256(_load(b, offset, WORD_SIZE));
    }

    /// @dev Bounds check, then the single `mload`. The word starts at the field's first byte, so the
    ///      field occupies its high-order bytes.
    function _load(bytes memory b, uint256 offset, uint256 size) private pure returns (bytes32 word) {
        uint256 length = b.length;
        if (offset > length || size > length - offset) revert MemoryReadOutOfBounds(offset, size, length);
        assembly ("memory-safe") {
            word := mload(add(add(b, 0x20), offset))
        }
    }
}
