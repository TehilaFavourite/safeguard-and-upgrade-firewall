// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Enum
/// @notice The Safe v1.5.0 operation type, value for value (lib/safe-smart-account/contracts/libraries/Enum.sol:9-12).
///         The guard's hook signatures encode it as `uint8`, so the order of the members is part of the ABI.
library Enum {
    enum Operation {
        Call, // 0
        DelegateCall // 1
    }
}
