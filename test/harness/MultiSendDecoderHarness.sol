// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {MultiSendDecoder} from "../../src/libraries/MultiSendDecoder.sol";

/// @notice Exposes the internal decoder library for direct tests (Phase 3).
contract MultiSendDecoderHarness {
    function decode(bytes memory data, address safe) external pure returns (MultiSendDecoder.Entry[] memory) {
        return MultiSendDecoder.decode(data, safe);
    }

    function maxBatchCalls() external pure returns (uint256) {
        return MultiSendDecoder.MAX_BATCH_CALLS;
    }
}
