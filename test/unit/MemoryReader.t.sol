// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {MemoryReader} from "../../src/libraries/MemoryReader.sol";

/// @notice Contingent on approval of the second assembly exception (Phase 3 proposal): read-only
///         MemoryReader, one bounds check plus one mload per function, never an mstore. Fuzzed against
///         a byte-by-byte Solidity reference, with exact out-of-bounds errors.
contract MemoryReaderHarness {
    function readUint8(bytes memory b, uint256 off) external pure returns (uint8) {
        return MemoryReader.readUint8(b, off);
    }

    function readAddress(bytes memory b, uint256 off) external pure returns (address) {
        return MemoryReader.readAddress(b, off);
    }

    function readUint256(bytes memory b, uint256 off) external pure returns (uint256) {
        return MemoryReader.readUint256(b, off);
    }

    function readBytes4(bytes memory b, uint256 off) external pure returns (bytes4) {
        return MemoryReader.readBytes4(b, off);
    }
}

contract MemoryReaderTest is Test {
    MemoryReaderHarness internal reader;

    function setUp() public {
        reader = new MemoryReaderHarness();
    }

    function _ref(bytes memory b, uint256 off, uint256 size) internal pure returns (uint256 acc) {
        for (uint256 k = 0; k < size; k++) {
            acc = (acc << 8) | uint8(b[off + k]);
        }
    }

    function _oob(uint256 off, uint256 size, uint256 len) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(MemoryReader.MemoryReadOutOfBounds.selector, off, size, len);
    }

    function _inBounds(uint256 off, uint256 size, uint256 len) internal pure returns (bool) {
        return off <= len && size <= len - off;
    }

    function testFuzz_MemoryReader_Uint8MatchesReference(bytes calldata b, uint256 off) public {
        if (_inBounds(off, 1, b.length)) {
            assertEq(reader.readUint8(b, off), uint8(_ref(b, off, 1)));
        } else {
            try reader.readUint8(b, off) returns (uint8) {
                fail();
            } catch (bytes memory err) {
                assertEq(err, _oob(off, 1, b.length));
            }
        }
    }

    function testFuzz_MemoryReader_AddressMatchesReference(bytes calldata b, uint256 off) public {
        if (_inBounds(off, 20, b.length)) {
            assertEq(reader.readAddress(b, off), address(uint160(_ref(b, off, 20))));
        } else {
            try reader.readAddress(b, off) returns (address) {
                fail();
            } catch (bytes memory err) {
                assertEq(err, _oob(off, 20, b.length));
            }
        }
    }

    function testFuzz_MemoryReader_Uint256MatchesReference(bytes calldata b, uint256 off) public {
        if (_inBounds(off, 32, b.length)) {
            assertEq(reader.readUint256(b, off), _ref(b, off, 32));
        } else {
            try reader.readUint256(b, off) returns (uint256) {
                fail();
            } catch (bytes memory err) {
                assertEq(err, _oob(off, 32, b.length));
            }
        }
    }

    function testFuzz_MemoryReader_Bytes4MatchesReference(bytes calldata b, uint256 off) public {
        if (_inBounds(off, 4, b.length)) {
            assertEq(uint32(reader.readBytes4(b, off)), uint32(_ref(b, off, 4)));
        } else {
            try reader.readBytes4(b, off) returns (bytes4) {
                fail();
            } catch (bytes memory err) {
                assertEq(err, _oob(off, 4, b.length));
            }
        }
    }

    /// @dev In-bounds reads with the offset concentrated near the end of the buffer, the boundary
    ///      where an off-by-one would show.
    function testFuzz_MemoryReader_ReadsAtBufferEnd(bytes calldata b) public view {
        vm.assume(b.length >= 32);
        assertEq(reader.readUint256(b, b.length - 32), _ref(b, b.length - 32, 32));
        assertEq(reader.readAddress(b, b.length - 20), address(uint160(_ref(b, b.length - 20, 20))));
        assertEq(reader.readUint8(b, b.length - 1), uint8(_ref(b, b.length - 1, 1)));
    }

    /// @dev Condition 1: `mload` reads 32 bytes, so a short field ending at the last byte of the buffer
    ///      also pulls in up to 31 bytes past the end. Here those bytes are made non-zero (0xff) by
    ///      shrinking the length of a larger buffer, which is test-only assembly. Every width read
    ///      ending exactly at the last byte must still equal the byte-by-byte reference.
    function testFuzz_MemoryReader_FieldEndingAtLastByteIgnoresTrailingMemory(bytes calldata raw) public view {
        vm.assume(raw.length >= 32);
        bytes memory b = abi.encodePacked(raw, bytes32(type(uint256).max));
        uint256 len = raw.length;
        assembly ("memory-safe") {
            mstore(b, len) // bytes after the new end are 0xff
        }
        assertEq(reader.readUint8(b, len - 1), uint8(_ref(b, len - 1, 1)), "uint8");
        assertEq(uint32(reader.readBytes4(b, len - 4)), uint32(_ref(b, len - 4, 4)), "bytes4");
        assertEq(reader.readAddress(b, len - 20), address(uint160(_ref(b, len - 20, 20))), "address");
        assertEq(reader.readUint256(b, len - 32), _ref(b, len - 32, 32), "uint256");
    }

    /// @dev Condition 2: overflow-safe bounds. Offsets within 64 of type(uint256).max, every width.
    function testFuzz_MemoryReader_OffsetNearMaxRevertsOutOfBounds(uint256 delta, uint8 which) public {
        uint256 off = type(uint256).max - bound(delta, 0, 64);
        bytes memory b = new bytes(64);
        uint256 w = uint256(which) % 4;
        uint256 size = w == 0 ? 1 : w == 1 ? 4 : w == 2 ? 20 : 32;
        vm.expectRevert(_oob(off, size, b.length));
        if (w == 0) reader.readUint8(b, off);
        else if (w == 1) reader.readBytes4(b, off);
        else if (w == 2) reader.readAddress(b, off);
        else reader.readUint256(b, off);
    }

    /// @dev An offset near 2^256 must not overflow `offset + size` into a Panic.
    function test_MemoryReader_HugeOffsetRevertsOutOfBounds() public {
        bytes memory b = new bytes(64);
        vm.expectRevert(_oob(type(uint256).max, 32, 64));
        reader.readUint256(b, type(uint256).max);
    }

    function test_MemoryReader_EmptyBufferRevertsOutOfBounds() public {
        vm.expectRevert(_oob(0, 1, 0));
        reader.readUint8("", 0);
    }
}
