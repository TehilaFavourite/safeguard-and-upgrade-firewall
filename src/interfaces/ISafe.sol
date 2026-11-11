// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ISafe
/// @notice The subset of the Safe v1.5.0 external API that the guard uses. Signatures match
///         lib/safe-smart-account/contracts/interfaces/ at the cited lines.
interface ISafe {
    /// @dev IStorageAccessible.sol:15
    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory);

    /// @dev IModuleManager.sol:81
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);

    /// @dev IOwnerManager.sol:62
    function getOwners() external view returns (address[] memory);

    /// @dev IOwnerManager.sol:50
    function getThreshold() external view returns (uint256);

    /// @dev IGuardManager.sol:21. Only its selector is used, to recognise the escape path (ADR 0014).
    function setGuard(address guard) external;

    /// @dev IModuleManager.sol:92. Only its selector is used, to recognise the escape path (ADR 0014).
    function setModuleGuard(address moduleGuard) external;
}
