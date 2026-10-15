// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Shared, ordered log of every call the recorders receive (differential test, I3.12).
contract CallLog {
    struct Rec {
        address target;
        uint256 value;
        bytes data;
    }

    Rec[] internal recs;

    function record(address target, uint256 value, bytes calldata data) external {
        recs.push(Rec({target: target, value: value, data: data}));
    }

    function count() external view returns (uint256) {
        return recs.length;
    }

    function get(uint256 i) external view returns (Rec memory) {
        return recs[i];
    }
}

/// @notice Records every call it receives into the shared log.
contract RecordingTarget {
    CallLog public immutable LOG;

    constructor(CallLog log) {
        LOG = log;
    }

    fallback() external payable {
        LOG.record(address(this), msg.value, msg.data);
    }

    receive() external payable {
        LOG.record(address(this), msg.value, "");
    }
}

/// @notice Stands in for the Safe: delegatecalls MultiSendCallOnly with a batch, as the Safe does
///         under `operation = DelegateCall`. Entries with `to == 0` call this contract itself
///         (MultiSendCallOnly.sol:44), and its fallback records them like any other target.
contract BatchRunner {
    CallLog public immutable LOG;

    constructor(CallLog log) {
        LOG = log;
    }

    /// @dev Unusual name, so fuzzed inner calldata is very unlikely to hit this selector.
    function runBatchThroughMultiSendCallOnlyX7(address multiSendCallOnly, bytes calldata data)
        external
        returns (bool ok, bytes memory ret)
    {
        (ok, ret) = multiSendCallOnly.delegatecall(data);
    }

    fallback() external payable {
        LOG.record(address(this), msg.value, msg.data);
    }

    receive() external payable {
        LOG.record(address(this), msg.value, "");
    }
}
