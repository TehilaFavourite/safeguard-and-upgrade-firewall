// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {MultiSendDecoder} from "../../src/libraries/MultiSendDecoder.sol";
import {MultiSendDecoderHarness} from "../harness/MultiSendDecoderHarness.sol";
import {BatchEncoding} from "../helpers/BatchEncoding.sol";

/// @notice I3.1-I3.8: the decoder alone. It is a pure library, so there's no Safe and no fork variant;
///         equivalence with the deployed MultiSendCallOnly is BatchDifferential.t.sol (both variants).
contract MultiSendDecoderTest is Test {
    using BatchEncoding for bytes;

    MultiSendDecoderHarness internal decoder;
    address internal safe;
    address internal alice;
    address internal bob;

    uint256 internal constant MAX_BATCH_CALLS = 32; // ADR 0003, D1

    function setUp() public {
        decoder = new MultiSendDecoderHarness();
        safe = makeAddr("safe");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
    }

    function _malformed(uint256 entryOffset) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(ISafeFirewallGuard.MultiSendMalformed.selector, entryOffset);
    }

    // ---------------------------------------------------------------- happy path

    function test_Decoder_DecodesSingleEntry() public view {
        bytes memory inner = hex"a9059cbb";
        bytes memory data = BatchEncoding.wrap(BatchEncoding.call(alice, 7, inner));

        MultiSendDecoder.Entry[] memory e = decoder.decode(data, safe);

        assertEq(e.length, 1);
        assertEq(e[0].to, alice);
        assertEq(e[0].value, 7);
        assertEq(e[0].dataOffset, BatchEncoding.WRAPPER + BatchEncoding.HEADER, "dataOffset is into `data`");
        assertEq(e[0].dataLength, inner.length);
    }

    function test_Decoder_DecodesMultipleEntriesInOrder() public view {
        bytes memory packed = abi.encodePacked(
            BatchEncoding.call(alice, 1, hex"01"),
            BatchEncoding.call(bob, 2, ""),
            BatchEncoding.call(alice, 3, hex"0203")
        );
        MultiSendDecoder.Entry[] memory e = decoder.decode(BatchEncoding.wrap(packed), safe);

        assertEq(e.length, 3);
        address[3] memory tos = [alice, bob, alice];
        uint256[3] memory lens = [uint256(1), 0, 2];
        uint256 offset = BatchEncoding.WRAPPER;
        for (uint256 i = 0; i < 3; i++) {
            assertEq(e[i].to, tos[i], "to");
            assertEq(e[i].value, i + 1, "value");
            assertEq(e[i].dataLength, lens[i], "dataLength");
            assertEq(e[i].dataOffset, offset + BatchEncoding.HEADER, "dataOffset");
            offset += BatchEncoding.HEADER + lens[i];
        }
    }

    /// @dev I3.6: `to == 0` means the Safe itself under delegatecall (MultiSendCallOnly.sol:44).
    function test_Decoder_ZeroToNormalizedToSafe() public view {
        MultiSendDecoder.Entry[] memory e =
            decoder.decode(BatchEncoding.wrap(BatchEncoding.call(address(0), 0, hex"deadbeef")), safe);
        assertEq(e[0].to, safe);
    }

    // ---------------------------------------------------------------- I3.1 selector

    function test_Decoder_WrongSelectorReverts() public {
        bytes memory data = BatchEncoding.wrap(BatchEncoding.call(alice, 0, ""));
        data[0] = 0x00;
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.MultiSendBadSelector.selector, bytes4(0x0080ff0a)));
        decoder.decode(data, safe);
    }

    function test_Decoder_ShorterThanSelectorReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.MultiSendBadSelector.selector, bytes4(0x8d80ff00)));
        decoder.decode(hex"8d80ff", safe);
    }

    // ---------------------------------------------------------------- I3.2 canonical wrapper, D3 padding

    function test_Decoder_TruncatedWrapperReverts() public {
        bytes memory data = abi.encodePacked(bytes4(0x8d80ff0a), uint256(0x20));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.MultiSendNotCanonical.selector, 0, 0, data.length));
        decoder.decode(data, safe);
    }

    function test_Decoder_NonCanonicalOffsetReverts() public {
        bytes memory packed = BatchEncoding.call(alice, 0, "");
        // Offset 0x40, with an extra word before the length: still decodable by Solidity, but not canonical.
        bytes memory data =
            abi.encodePacked(bytes4(0x8d80ff0a), uint256(0x40), uint256(0), uint256(packed.length), packed);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.MultiSendNotCanonical.selector, 0x40, 0, data.length));
        decoder.decode(data, safe);
    }

    function test_Decoder_ExtraWordAfterBatchReverts() public {
        bytes memory packed = BatchEncoding.call(alice, 0, "");
        bytes memory data = abi.encodePacked(BatchEncoding.wrap(packed), uint256(0));
        vm.expectRevert(
            abi.encodeWithSelector(ISafeFirewallGuard.MultiSendNotCanonical.selector, 0x20, packed.length, data.length)
        );
        decoder.decode(data, safe);
    }

    function test_Decoder_DeclaredLengthPastDataReverts() public {
        bytes memory packed = BatchEncoding.call(alice, 0, "");
        bytes memory data = BatchEncoding.wrap(packed);
        // Overwrite the ABI length word (bytes 36..67) with a larger value.
        uint256 declared = packed.length + 64;
        for (uint256 i = 0; i < 32; i++) {
            // forge-lint: disable-next-line(unsafe-typecast)
            data[36 + i] = bytes1(uint8(declared >> (8 * (31 - i)))); // intended: extract one byte
        }
        vm.expectRevert(
            abi.encodeWithSelector(ISafeFirewallGuard.MultiSendNotCanonical.selector, 0x20, declared, data.length)
        );
        decoder.decode(data, safe);
    }

    /// @dev D3: one 85-byte entry leaves 11 padding bytes in the last ABI word. Each must be zero.
    function testFuzz_Decoder_NonZeroPaddingReverts(uint8 which, uint8 junk) public {
        vm.assume(junk != 0);
        bytes memory packed = BatchEncoding.call(alice, 0, ""); // 85 bytes
        bytes memory data = BatchEncoding.wrap(packed); // 4 + 32 + 32 + 96
        uint256 padStart = BatchEncoding.WRAPPER + packed.length;
        uint256 position = padStart + bound(which, 0, data.length - padStart - 1);
        data[position] = bytes1(junk);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.MultiSendPaddingNotZero.selector, position));
        decoder.decode(data, safe);
    }

    // ---------------------------------------------------------------- I3.3 empty

    function test_Decoder_EmptyBatchReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.EmptyBatch.selector));
        decoder.decode(BatchEncoding.wrap(""), safe);
    }

    // ---------------------------------------------------------------- I3.4 strict tiling

    /// @dev 1-84 trailing bytes can't hold a header. MultiSendCallOnly ignores up to 32 of them and
    ///      parses more than 32 as another entry (ADR 0003). The guard rejects them all.
    function testFuzz_Decoder_TrailingBytesReverts(uint8 trailing) public {
        uint256 t = bound(trailing, 1, BatchEncoding.HEADER - 1);
        bytes memory first = BatchEncoding.call(alice, 0, "");
        bytes memory packed = abi.encodePacked(first, new bytes(t));
        vm.expectRevert(_malformed(first.length));
        decoder.decode(BatchEncoding.wrap(packed), safe);
    }

    function test_Decoder_TrailingBytesBoundaries() public {
        uint256[4] memory ts = [uint256(1), 32, 33, 84];
        bytes memory first = BatchEncoding.call(alice, 0, "");
        for (uint256 i = 0; i < ts.length; i++) {
            vm.expectRevert(_malformed(first.length));
            decoder.decode(BatchEncoding.wrap(abi.encodePacked(first, new bytes(ts[i]))), safe);
        }
    }

    function test_Decoder_TruncatedHeaderReverts() public {
        bytes memory packed = BatchEncoding.call(alice, 0, "");
        bytes memory truncated = new bytes(packed.length - 1);
        for (uint256 i = 0; i < truncated.length; i++) {
            truncated[i] = packed[i];
        }
        vm.expectRevert(_malformed(0));
        decoder.decode(BatchEncoding.wrap(truncated), safe);
    }

    /// @dev dataLength one byte longer than the bytes left. MultiSendCallOnly would read past its
    ///      buffer (MultiSendCallOnly.sol:48-54).
    function test_Decoder_DataLengthPastBufferReverts() public {
        bytes memory inner = hex"aabbcc";
        bytes memory packed = abi.encodePacked(uint8(0), alice, uint256(0), uint256(inner.length + 1), inner);
        vm.expectRevert(_malformed(0));
        decoder.decode(BatchEncoding.wrap(packed), safe);
    }

    /// @dev A dataLength near 2^256 must be caught as Malformed, not overflow into a Panic.
    function test_Decoder_HugeDataLengthRevertsMalformed() public {
        bytes memory packed = abi.encodePacked(uint8(0), alice, uint256(0), type(uint256).max);
        vm.expectRevert(_malformed(0));
        decoder.decode(BatchEncoding.wrap(packed), safe);
    }

    function test_Decoder_MalformedSecondEntryReportsItsOffset() public {
        bytes memory first = BatchEncoding.call(alice, 0, hex"01");
        bytes memory packed = abi.encodePacked(first, uint8(0), bob, uint256(0), uint256(5), hex"0102");
        vm.expectRevert(_malformed(first.length));
        decoder.decode(BatchEncoding.wrap(packed), safe);
    }

    // ---------------------------------------------------------------- I3.5 operation byte

    function test_Decoder_InnerDelegateCallRejectedByGuard() public {
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.InnerOperationNotAllowed.selector, 0, uint8(1)));
        decoder.decode(BatchEncoding.wrap(BatchEncoding.entry(1, alice, 0, "")), safe);
    }

    function testFuzz_Decoder_NonZeroOperationReverts(uint8 op) public {
        vm.assume(op != 0);
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.InnerOperationNotAllowed.selector, 0, op));
        decoder.decode(BatchEncoding.wrap(BatchEncoding.entry(op, alice, 0, "")), safe);
    }

    function test_Decoder_OperationErrorReportsEntryIndex() public {
        bytes memory packed = abi.encodePacked(
            BatchEncoding.call(alice, 0, ""), BatchEncoding.call(bob, 0, ""), BatchEncoding.entry(1, alice, 0, "")
        );
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.InnerOperationNotAllowed.selector, 2, uint8(1)));
        decoder.decode(BatchEncoding.wrap(packed), safe);
    }

    // ---------------------------------------------------------------- I3.7 bound (D1)

    function _nCalls(uint256 n) internal view returns (bytes memory packed) {
        for (uint256 i = 0; i < n; i++) {
            packed = abi.encodePacked(packed, BatchEncoding.call(alice, i, ""));
        }
    }

    function test_Decoder_MaxBatchCallsAccepted() public view {
        assertEq(decoder.maxBatchCalls(), MAX_BATCH_CALLS);
        assertEq(decoder.decode(BatchEncoding.wrap(_nCalls(MAX_BATCH_CALLS)), safe).length, MAX_BATCH_CALLS);
    }

    function test_Decoder_TooManyBatchCallsReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.TooManyBatchCalls.selector, MAX_BATCH_CALLS));
        decoder.decode(BatchEncoding.wrap(_nCalls(MAX_BATCH_CALLS + 1)), safe);
    }

    // ---------------------------------------------------------------- I3.8 rejections use known errors only

    function _isKnownDecoderError(bytes memory err) internal pure returns (bool) {
        if (err.length < 4) return false;
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes4 sel = bytes4(err); // intended: the error selector
        return sel == ISafeFirewallGuard.MultiSendBadSelector.selector
            || sel == ISafeFirewallGuard.MultiSendNotCanonical.selector
            || sel == ISafeFirewallGuard.MultiSendPaddingNotZero.selector
            || sel == ISafeFirewallGuard.EmptyBatch.selector || sel == ISafeFirewallGuard.MultiSendMalformed.selector
            || sel == ISafeFirewallGuard.InnerOperationNotAllowed.selector
            || sel == ISafeFirewallGuard.TooManyBatchCalls.selector;
    }

    function _assertAcceptedOrKnownError(bytes memory data) internal view {
        try decoder.decode(data, safe) returns (MultiSendDecoder.Entry[] memory) {}
        catch (bytes memory err) {
            assertTrue(_isKnownDecoderError(err), "rejection is not a decoder custom error (Panic / out-of-gas?)");
        }
    }

    /// @dev Raw random bytes: mostly rejected at the selector or wrapper.
    function testFuzz_Decoder_RandomBytesOnlyKnownErrors(bytes calldata data) public view {
        _assertAcceptedOrKnownError(data);
    }

    /// @dev Random payload inside a canonical wrapper, so the fuzzer reaches the entry parser.
    function testFuzz_Decoder_RandomPayloadOnlyKnownErrors(bytes calldata payload) public view {
        _assertAcceptedOrKnownError(BatchEncoding.wrap(payload));
    }

    /// @dev Random packed entries with plausible headers: exercises tiling, lengths and the bound.
    function testFuzz_Decoder_RandomEntriesOnlyKnownErrors(uint8 op, uint256 declaredLength, bytes calldata tail)
        public
        view
    {
        bytes memory packed = abi.encodePacked(op, alice, uint256(0), declaredLength, tail);
        _assertAcceptedOrKnownError(BatchEncoding.wrap(packed));
    }
}
