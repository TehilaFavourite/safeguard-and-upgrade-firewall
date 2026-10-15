// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ISafeFirewallGuard} from "../interfaces/ISafeFirewallGuard.sol";
import {MemoryReader} from "./MemoryReader.sol";

/// @title MultiSendDecoder
/// @notice Strict decoder for `MultiSendCallOnly.multiSend(bytes)` calldata (ADR 0003).
/// @dev One accepted encoding per batch: anything two encodings could mean differently is rejected,
///      because the gap between what signers see and what executes is the attack. Accepted batches are
///      executed by MultiSendCallOnly exactly as decoded (differential test, I3.12). The decoder never
///      copies data: each entry is returned as offsets into `data`, and policy reads fields in place.
///      Packed entry layout (lib/safe-smart-account/contracts/libraries/MultiSendCallOnly.sol:13-18):
///      operation (1 byte) | to (20) | value (32) | dataLength (32) | data (dataLength).
library MultiSendDecoder {
    /// @notice One inner call. `dataOffset` and `dataLength` locate its calldata inside `data`.
    struct Entry {
        address to;
        uint256 value;
        uint256 dataOffset;
        uint256 dataLength;
    }

    /// @dev `multiSend(bytes)`, MultiSendCallOnly.sol:25.
    bytes4 internal constant MULTISEND_SELECTOR = 0x8d80ff0a;
    /// @dev ADR 0003, D1.
    uint256 internal constant MAX_BATCH_CALLS = 32;

    uint256 private constant SELECTOR_SIZE = 4;
    uint256 private constant WORD = 32;
    /// @dev Position of the ABI offset word and of the length word.
    uint256 private constant OFFSET_WORD_POS = 4;
    uint256 private constant LENGTH_WORD_POS = 36;
    /// @dev selector + offset word + length word; the packed transactions start here.
    uint256 private constant PAYLOAD_START = 68;
    /// @dev The only accepted ABI offset for the single `bytes` argument.
    uint256 private constant CANONICAL_OFFSET = 0x20;
    /// @dev Operation (1) + to (20) + value (32) + dataLength (32).
    uint256 private constant HEADER_SIZE = 85;
    uint256 private constant TO_POS = 1;
    uint256 private constant VALUE_POS = 21;
    uint256 private constant LENGTH_POS = 53;
    /// @dev MultiSendCallOnly executes only operation 0 (MultiSendCallOnly.sol:53).
    uint8 private constant OPERATION_CALL = 0;

    /// @notice Decodes and validates `data`, the calldata of a delegatecall to MultiSendCallOnly.
    /// @param safe The account the batch executes as. An inner `to == address(0)` means this account
    ///        (MultiSendCallOnly.sol:44), and is normalized to it.
    /// @return entries The inner calls, in execution order.
    function decode(bytes memory data, address safe) internal pure returns (Entry[] memory entries) {
        uint256 length = _requireCanonicalWrapper(data);

        Entry[] memory buffer = new Entry[](MAX_BATCH_CALLS);
        uint256 count = 0;
        uint256 pos = 0; // relative to PAYLOAD_START
        while (pos < length) {
            if (count == MAX_BATCH_CALLS) revert ISafeFirewallGuard.TooManyBatchCalls(MAX_BATCH_CALLS);
            if (length - pos < HEADER_SIZE) revert ISafeFirewallGuard.MultiSendMalformed(pos);

            uint256 at = PAYLOAD_START + pos;
            uint8 operation = MemoryReader.readUint8(data, at);
            if (operation != OPERATION_CALL) revert ISafeFirewallGuard.InnerOperationNotAllowed(count, operation);

            uint256 dataLength = MemoryReader.readUint256(data, at + LENGTH_POS);
            // Subtraction form: a dataLength near 2^256 can't overflow.
            if (dataLength > length - pos - HEADER_SIZE) revert ISafeFirewallGuard.MultiSendMalformed(pos);

            address to = MemoryReader.readAddress(data, at + TO_POS);
            buffer[count] = Entry({
                to: to == address(0) ? safe : to,
                value: MemoryReader.readUint256(data, at + VALUE_POS),
                dataOffset: at + HEADER_SIZE,
                dataLength: dataLength
            });
            count++;
            pos += HEADER_SIZE + dataLength;
        }

        entries = new Entry[](count);
        for (uint256 i = 0; i < count; i++) {
            entries[i] = buffer[i];
        }
    }

    /// @notice The first 4 bytes of an entry's calldata, zero-padded when shorter. This matches how a
    ///         top-level call's selector is reported (`bytes4(data)`).
    function selectorOf(bytes memory data, Entry memory entry) internal pure returns (bytes4 selector) {
        if (entry.dataLength >= SELECTOR_SIZE) return MemoryReader.readBytes4(data, entry.dataOffset);
        for (uint256 i = 0; i < entry.dataLength; i++) {
            selector |= bytes4(bytes1(MemoryReader.readUint8(data, entry.dataOffset + i))) >> (8 * i);
        }
    }

    /// @dev Selector, canonical ABI wrapper, zero padding and non-empty payload. Returns the payload
    ///      length.
    function _requireCanonicalWrapper(bytes memory data) private pure returns (uint256 length) {
        bytes4 selector = _selector(data);
        if (selector != MULTISEND_SELECTOR) revert ISafeFirewallGuard.MultiSendBadSelector(selector);
        if (data.length < PAYLOAD_START) revert ISafeFirewallGuard.MultiSendNotCanonical(0, 0, data.length);

        uint256 offsetWord = MemoryReader.readUint256(data, OFFSET_WORD_POS);
        length = MemoryReader.readUint256(data, LENGTH_WORD_POS);
        if (offsetWord != CANONICAL_OFFSET || length > data.length - PAYLOAD_START) {
            revert ISafeFirewallGuard.MultiSendNotCanonical(offsetWord, length, data.length);
        }
        uint256 padded = length + ((WORD - (length % WORD)) % WORD);
        if (PAYLOAD_START + padded != data.length) {
            revert ISafeFirewallGuard.MultiSendNotCanonical(offsetWord, length, data.length);
        }
        for (uint256 p = PAYLOAD_START + length; p < data.length; p++) {
            if (MemoryReader.readUint8(data, p) != 0) revert ISafeFirewallGuard.MultiSendPaddingNotZero(p);
        }
        if (length == 0) revert ISafeFirewallGuard.EmptyBatch();
    }

    /// @dev The first 4 bytes, zero-padded when `data` is shorter.
    function _selector(bytes memory data) private pure returns (bytes4 selector) {
        if (data.length >= SELECTOR_SIZE) return MemoryReader.readBytes4(data, 0);
        for (uint256 i = 0; i < data.length; i++) {
            selector |= bytes4(bytes1(MemoryReader.readUint8(data, i))) >> (8 * i);
        }
    }
}
