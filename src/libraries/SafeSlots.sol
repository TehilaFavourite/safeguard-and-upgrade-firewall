// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {ISafe} from "safe-smart-account/contracts/interfaces/ISafe.sol";

import {ISafeFirewallGuard} from "../interfaces/ISafeFirewallGuard.sol";

/// @notice The proxy's own `masterCopy()` shortcut, answered from slot 0 by the proxy bytecode without
///         delegating to the singleton (lib/safe-smart-account/contracts/proxies/SafeProxy.sol:42-45).
interface ISafeProxyMasterCopy {
    function masterCopy() external view returns (address);
}

/// @title SafeSlots
/// @notice Safe v1.5.0 storage locations and read helpers for the protected-state check (ADR 0020).
///         Every constant is taken from the installed Safe source, cited at its definition.
library SafeSlots {
    /// @dev `address internal singleton;`, lib/safe-smart-account/contracts/libraries/SafeStorage.sol:11
    uint256 internal constant SINGLETON_SLOT = 0;
    /// @dev `uint256 internal threshold;`, SafeStorage.sol:17
    uint256 internal constant THRESHOLD_SLOT = 4;
    /// @dev keccak256("guard_manager.guard.address"), lib/safe-smart-account/contracts/base/GuardManager.sol:66
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    /// @dev keccak256("module_manager.module_guard.address"), lib/safe-smart-account/contracts/base/ModuleManager.sol:65
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    /// @dev keccak256("fallback_manager.handler.address"), lib/safe-smart-account/contracts/base/FallbackManager.sol:13
    bytes32 internal constant FALLBACK_HANDLER_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    /// @dev `SENTINEL_MODULES`, ModuleManager.sol:62
    address internal constant SENTINEL_MODULES = address(0x1);
    /// @dev Maximum number of modules the guard reads in full (ADR 0020, D3).
    uint256 internal constant MAX_MODULES = 16;
    /// @dev `getStorageAt` length argument for a single 32-byte word.
    uint256 private constant ONE_WORD = 1;

    /// @notice The Safe's singleton as reported by the proxy itself. Read this first: it is the only
    ///         read that doesn't execute singleton code (ADR 0020, decision 1).
    function masterCopy(address safe) internal view returns (address) {
        return ISafeProxyMasterCopy(safe).masterCopy();
    }

    /// @notice The raw 32-byte word at `slot`, via `StorageAccessible.getStorageAt`. Only trustworthy
    ///         once `masterCopy` has been checked.
    function word(address safe, bytes32 slot) internal view returns (bytes32) {
        return abi.decode(ISafe(payable(safe)).getStorageAt(uint256(slot), ONE_WORD), (bytes32));
    }

    /// @notice `keccak256(abi.encode(modules))` of the full module list.
    /// @dev Reads at most MAX_MODULES + 1 entries, which bounds the Safe's loop (ModuleManager.sol:212).
    ///      - MAX_MODULES + 1 entries returned: over the limit, or a cycle → `TooManyModules`.
    ///      - Fewer entries but `next` isn't the sentinel: the list ended at address(0)
    ///        (ModuleManager.sol:226-227) → `ModuleListNotTerminated`.
    function modulesHash(address safe) internal view returns (bytes32) {
        (address[] memory list, address next) =
            ISafe(payable(safe)).getModulesPaginated(SENTINEL_MODULES, MAX_MODULES + 1);
        if (list.length > MAX_MODULES) revert ISafeFirewallGuard.TooManyModules(MAX_MODULES);
        if (next != SENTINEL_MODULES) revert ISafeFirewallGuard.ModuleListNotTerminated(next);
        return keccak256(abi.encode(list));
    }

    /// @notice `keccak256(abi.encode(owners))` of the owner list. An unterminated list makes the Safe's
    ///         own `getOwners()` revert, so the read fails closed (ADR 0020).
    function ownersHash(address safe) internal view returns (bytes32) {
        return keccak256(abi.encode(ISafe(payable(safe)).getOwners()));
    }

    /// @notice The threshold, via `getThreshold()`.
    function threshold(address safe) internal view returns (uint256) {
        return ISafe(payable(safe)).getThreshold();
    }
}
