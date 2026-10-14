// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice The decoded Bybit hack payload (docs/bybit-incident.md §4, tx
///         0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882), as a test fixture.
library BybitPayload {
    /// @dev `to` of the hack execTransaction: the attacker's delegate contract (172 bytes, only
    ///      function `transfer(address,uint256)`; code present at both pinned fork blocks).
    address internal constant ATTACKER_DELEGATE = 0x96221423681A6d52E184D440a8eFCEbB105C7242;
    /// @dev First argument of the disguised `transfer`, which ends up in slot 0 (§1).
    address internal constant ATTACKER_SINGLETON = 0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516;
    /// @dev `safeTxGas` of the hack transaction.
    uint256 internal constant SAFE_TX_GAS = 45_746;
    /// @dev `operation` of the hack transaction: 1 = DelegateCall.
    uint8 internal constant OPERATION = 1;

    /// @dev `data` of the hack transaction: transfer(ATTACKER_SINGLETON, 0), selector 0xa9059cbb.
    function data() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transfer(address,uint256)", ATTACKER_SINGLETON, uint256(0));
    }

    /// @dev Same shape with a different slot-0 value, for the lying-singleton test (I2.13).
    function dataWithSingleton(address singleton) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transfer(address,uint256)", singleton, uint256(0));
    }
}
