// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {IGuardFactory} from "./interfaces/IGuardFactory.sol";
import {ISafeFirewallGuard} from "./interfaces/ISafeFirewallGuard.sol";
import {SafeFirewallGuard} from "./SafeFirewallGuard.sol";

/// @title GuardFactory
/// @notice Permissionless, idempotent CREATE2 factory for per-Safe guards (ADR 0007).
contract GuardFactory is IGuardFactory {
    /// @inheritdoc IGuardFactory
    bytes32 public constant override VERSION = "safe-firewall-guard/v1";

    /// @dev EIP-1014: address = keccak256(0xff ++ deployer ++ salt ++ keccak256(initCode))[12:].
    bytes1 private constant CREATE2_PREFIX = 0xff;

    /// @inheritdoc IGuardFactory
    /// @dev If the guard already exists, returns it without redeploying or emitting (ADR 0007).
    ///      Code at the predicted address can only come from this factory, with this salt and this
    ///      init code (EIP-1014), so existing code there is always this exact guard.
    function deploy(ISafeFirewallGuard.FirewallConfig calldata config) external override returns (address guard) {
        bytes32 salt = _salt(config.safe);
        guard = _predict(config, salt);
        if (guard.code.length != 0) return guard;

        guard = address(new SafeFirewallGuard{salt: salt}(config));
        emit GuardDeployed(config.safe, guard, keccak256(abi.encode(config)));
    }

    /// @inheritdoc IGuardFactory
    function predict(ISafeFirewallGuard.FirewallConfig calldata config) external view override returns (address) {
        return _predict(config, _salt(config.safe));
    }

    /// @dev salt = keccak256(abi.encode(safe, VERSION)) (ADR 0007).
    function _salt(address safe) private pure returns (bytes32) {
        return keccak256(abi.encode(safe, VERSION));
    }

    function _predict(ISafeFirewallGuard.FirewallConfig calldata config, bytes32 salt) private view returns (address) {
        bytes32 initCodeHash = keccak256(abi.encodePacked(type(SafeFirewallGuard).creationCode, abi.encode(config)));
        return address(uint160(uint256(keccak256(abi.encodePacked(CREATE2_PREFIX, address(this), salt, initCodeHash)))));
    }
}
