// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {ISafeFirewallGuard} from "./ISafeFirewallGuard.sol";

/// @title IGuardFactory
/// @notice CREATE2 factory for per-Safe guards (ADR 0007).
interface IGuardFactory {
    /// @notice `deploy` was called by an address other than `config.safe` (ADR 0007).
    error NotSafe(address caller, address safe);

    /// @notice A guard was deployed for `safe`.
    /// @param configHash `keccak256(abi.encode(config))`, so the alert bot can match a deployment to
    ///        the reviewed config.
    event GuardDeployed(address indexed safe, address indexed guard, bytes32 indexed configHash);

    /// @notice Version tag mixed into the CREATE2 salt: `salt = keccak256(abi.encode(safe, VERSION))`.
    function VERSION() external view returns (bytes32);

    /// @notice Deploys a guard for `config.safe`. Reverts with `NotSafe` unless
    ///         `msg.sender == config.safe`.
    function deploy(ISafeFirewallGuard.FirewallConfig calldata config) external returns (address guard);

    /// @notice The address `deploy(config)` will deploy to.
    function predict(ISafeFirewallGuard.FirewallConfig calldata config) external view returns (address guard);
}
