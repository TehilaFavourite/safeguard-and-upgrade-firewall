// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {MultiSendDecoder} from "../../src/libraries/MultiSendDecoder.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";
import {MultiSendDecoderHarness} from "../harness/MultiSendDecoderHarness.sol";
import {BatchEncoding} from "../helpers/BatchEncoding.sol";
import {CallLog, RecordingTarget, BatchRunner} from "../mocks/Recorders.sol";

/// @notice I3.12-I3.13: every batch the decoder accepts executes through MultiSendCallOnly exactly as
///         decoded: same targets (to == 0 mapped to the executing account), values and calldata, in the
///         same order. The unit variant runs the local MultiSendCallOnly; the fork variant runs the
///         canonical deployed bytecode (solc 0.7.6).
abstract contract BatchDifferentialTest is FirewallTestBase {
    uint256 internal constant TARGETS = 3;
    uint256 internal constant MAX_FUZZ_ENTRIES = 8;
    uint256 internal constant MAX_FUZZ_DATA = 96;
    uint256 internal constant MAX_FUZZ_VALUE = 1e15;

    MultiSendDecoderHarness internal decoder;
    CallLog internal callLog;
    BatchRunner internal runner;
    address[TARGETS] internal targets;

    function setUp() public virtual override {
        super.setUp();
        decoder = new MultiSendDecoderHarness();
        callLog = new CallLog();
        runner = new BatchRunner(callLog);
        vm.deal(address(runner), 100 ether);
        for (uint256 i = 0; i < TARGETS; i++) {
            targets[i] = address(new RecordingTarget(callLog));
        }
    }

    // ---------------------------------------------------------------- generators

    /// @dev A well-formed batch. Target choice 0 means `to == address(0)`, otherwise a recorder.
    function _generate(uint256 seed, uint256 n) internal view returns (bytes memory packed) {
        for (uint256 i = 0; i < n; i++) {
            uint256 r = uint256(keccak256(abi.encode(seed, i)));
            uint256 choice = r % (TARGETS + 1);
            address to = choice == 0 ? address(0) : targets[choice - 1];
            uint256 value = (r >> 8) % MAX_FUZZ_VALUE;
            bytes memory data = _randomBytes(r >> 64, (r >> 32) % (MAX_FUZZ_DATA + 1));
            packed = abi.encodePacked(packed, BatchEncoding.call(to, value, data));
        }
    }

    function _randomBytes(uint256 seed, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i)))));
        }
    }

    function _slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[start + i];
        }
    }

    // ---------------------------------------------------------------- the differential check

    /// @dev If the decoder accepts `data`, MultiSendCallOnly must execute exactly the decoded calls.
    ///      If it rejects, the rejection must be a decoder custom error (I3.8). Returns whether it accepted.
    function _checkEquivalent(bytes memory data) internal returns (bool accepted) {
        MultiSendDecoder.Entry[] memory entries;
        try decoder.decode(data, address(runner)) returns (MultiSendDecoder.Entry[] memory e) {
            entries = e;
        } catch (bytes memory err) {
            assertTrue(err.length >= 4, "decoder rejected without a custom error");
            return false;
        }

        uint256 before = callLog.count();
        (bool ok,) = runner.runBatchThroughMultiSendCallOnlyX7(infra.multiSendCallOnly, data);
        assertTrue(ok, "MultiSendCallOnly reverted on a batch the decoder accepted");
        assertEq(callLog.count() - before, entries.length, "call count differs");

        for (uint256 i = 0; i < entries.length; i++) {
            CallLog.Rec memory rec = callLog.get(before + i);
            assertEq(rec.target, entries[i].to, "target differs");
            assertEq(rec.value, entries[i].value, "value differs");
            assertEq(rec.data, _slice(data, entries[i].dataOffset, entries[i].dataLength), "calldata differs");
        }
        return true;
    }

    // ---------------------------------------------------------------- structured fuzz

    function testFuzz_Differential_WellFormedBatchesExecuteAsDecoded(uint256 seed, uint8 n) public {
        uint256 count = bound(n, 1, MAX_FUZZ_ENTRIES);
        assertTrue(_checkEquivalent(BatchEncoding.wrap(_generate(seed, count))), "well-formed batch rejected");
    }

    // ---------------------------------------------------------------- mutation fuzz

    /// @dev Mutations of a valid batch: truncate, extend, or alter one entry's dataLength. Whatever the
    ///      decoder still accepts must execute as decoded.
    function testFuzz_Differential_MutatedBatches(uint256 seed, uint8 n, uint8 kind, uint16 amount) public {
        bytes memory packed = _generate(seed, bound(n, 1, MAX_FUZZ_ENTRIES));
        uint256 m = uint256(kind) % 3;
        if (m == 0) {
            uint256 cut = bound(amount, 1, packed.length);
            packed = _slice(packed, 0, packed.length - cut);
        } else if (m == 1) {
            packed = abi.encodePacked(packed, _randomBytes(seed ^ 0xA5, bound(amount, 1, 200)));
        } else {
            // Add a signed delta to the first entry's dataLength field (bytes 53..84).
            uint256 declared;
            for (uint256 i = 0; i < 32; i++) {
                declared = (declared << 8) | uint8(packed[53 + i]);
            }
            uint256 delta = bound(amount, 1, 200);
            uint256 mutated = (seed & 1) == 0 ? declared + delta : (declared >= delta ? declared - delta : 0);
            for (uint256 i = 0; i < 32; i++) {
                // forge-lint: disable-next-line(unsafe-typecast)
                packed[53 + i] = bytes1(uint8(mutated >> (8 * (31 - i)))); // intended: extract one byte
            }
        }
        _checkEquivalent(BatchEncoding.wrap(packed));
    }

    // ---------------------------------------------------------------- I3.13 why the strictness matters

    /// @dev MultiSendCallOnly silently ignores up to 32 trailing bytes (its loop runs while i < length,
    ///      with i starting at 0x20; MultiSendCallOnly.sol:30-33). Signers might believe those bytes mean
    ///      something. The decoder rejects them.
    function test_Differential_MultiSendIgnoresTrailingBytesDecoderRejects() public {
        bytes memory valid = BatchEncoding.call(targets[0], 1, hex"01");
        bytes memory data = BatchEncoding.wrap(abi.encodePacked(valid, new bytes(20)));

        uint256 before = callLog.count();
        (bool ok,) = runner.runBatchThroughMultiSendCallOnlyX7(infra.multiSendCallOnly, data);
        assertTrue(ok, "MultiSendCallOnly accepts the trailing bytes");
        assertEq(callLog.count() - before, 1, "MultiSendCallOnly executed only the valid entry");

        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.MultiSendMalformed.selector, valid.length));
        decoder.decode(data, address(runner));
    }

    /// @dev With dataLength larger than the bytes present, MultiSendCallOnly passes the declared length
    ///      to CALL and reads past its buffer (MultiSendCallOnly.sol:48-54). The target receives calldata
    ///      the batch never contained. The decoder rejects it.
    function test_Differential_MultiSendReadsPastBufferDecoderRejects() public {
        bytes memory inner = hex"aabbccdd";
        uint256 declared = inner.length + 8;
        bytes memory packed = abi.encodePacked(uint8(0), targets[0], uint256(0), declared, inner);
        bytes memory data = BatchEncoding.wrap(packed);

        uint256 before = callLog.count();
        (bool ok,) = runner.runBatchThroughMultiSendCallOnlyX7(infra.multiSendCallOnly, data);
        if (ok && callLog.count() > before) {
            assertEq(callLog.get(before).data.length, declared, "MultiSendCallOnly sent the declared length");
        }

        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.MultiSendMalformed.selector, 0));
        decoder.decode(data, address(runner));
    }
}

contract BatchDifferentialUnitTest is BatchDifferentialTest, LocalSafe {
    function setUp() public override(BatchDifferentialTest, FirewallTestBase) {
        BatchDifferentialTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract BatchDifferentialForkTest is BatchDifferentialTest, FeatureForkSafe {
    function setUp() public override(BatchDifferentialTest, FirewallTestBase) {
        BatchDifferentialTest.setUp();
    }
}
