// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ISafeFirewallGuard} from "./ISafeFirewallGuard.sol";

/// @title IGuardFactory
/// @notice Permissionless, idempotent CREATE2 factory for per-Safe guards (ADR 0007).
interface IGuardFactory {
    /// @notice A guard was deployed for `safe`. Not emitted when `deploy` returns an existing guard.
    /// @param configHash `keccak256(abi.encode(config))`, so the alert bot can match a deployment to
    ///        the reviewed config.
    event GuardDeployed(address indexed safe, address indexed guard, bytes32 indexed configHash);

    /// @notice Version tag mixed into the CREATE2 salt: `salt = keccak256(abi.encode(safe, VERSION))`.
    function VERSION() external view returns (bytes32);

    /// @notice Deploys the guard for `config`, or returns it if it already exists. Anyone may call.
    /// @dev Constructor-only config ties the address to the config, so a front-runner can only
    ///      deploy the identical guard. Idempotence means that never makes this call revert
    ///      (ADR 0007). Replacement guards for the escape path are deployed this way, outside the
    ///      Safe (ADR 0014).
    function deploy(ISafeFirewallGuard.FirewallConfig calldata config) external returns (address guard);

    /// @notice The address `deploy(config)` deploys to, or returns.
    function predict(ISafeFirewallGuard.FirewallConfig calldata config) external view returns (address guard);
}
