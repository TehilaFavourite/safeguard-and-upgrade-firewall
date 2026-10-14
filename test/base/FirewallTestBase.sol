// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ISafe} from "safe-smart-account/contracts/interfaces/ISafe.sol";
import {IModuleManager} from "safe-smart-account/contracts/interfaces/IModuleManager.sol";
import {IGuardManager} from "safe-smart-account/contracts/interfaces/IGuardManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";
import {SafeProxyFactory} from "safe-smart-account/contracts/proxies/SafeProxyFactory.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {SafeFirewallGuardHarness} from "../harness/SafeFirewallGuardHarness.sol";
import {TestModule} from "../mocks/TestModule.sol";

/// @notice Shared setup for every feature test. Concrete Safe sources come from `_deploySafe()`,
///         implemented by `LocalSafe` (local 0.8.28 build) and `ForkSafe` (mainnet v1.5.0) (ADR 0013).
abstract contract FirewallTestBase is Test {
    // keccak256("guard_manager.guard.address"), lib/safe-smart-account/contracts/base/GuardManager.sol:66
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    // keccak256("module_manager.module_guard.address"), lib/safe-smart-account/contracts/base/ModuleManager.sol:65
    bytes32 internal constant MODULE_GUARD_STORAGE_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    uint256 internal constant OWNER_COUNT = 3;
    uint256 internal constant THRESHOLD = 2;
    uint256 internal constant SAFE_SALT_NONCE = 1;
    uint256 internal constant SAFE_STARTING_BALANCE = 10 ether;
    /// @dev Non-zero `safeTxGas` makes `execTransaction` return false instead of reverting when the
    ///      inner call fails (lib/safe-smart-account/contracts/Safe.sol:184).
    uint256 internal constant NON_ZERO_SAFE_TX_GAS = 100_000;

    struct SafeInfra {
        address singleton;
        address proxyFactory;
        address fallbackHandler;
        address multiSendCallOnly;
        address permit2;
    }

    SafeInfra internal infra;
    ISafe internal safe;
    address[] internal owners;
    mapping(address owner => uint256 key) internal ownerKey;
    TestModule internal module;
    SafeFirewallGuardHarness internal guard;

    /// @notice Supplies the Safe singleton, proxy factory and canonical addresses for this variant.
    ///         Returns a zero struct when the variant is skipped.
    function _deploySafe() internal virtual returns (SafeInfra memory);

    function setUp() public virtual {
        infra = _deploySafe();
        if (infra.singleton == address(0)) return; // variant skipped

        _createOwners();
        safe = _createSafe();
        vm.deal(address(safe), SAFE_STARTING_BALANCE);

        module = new TestModule();
        _execSigned(
            address(safe), 0, abi.encodeCall(IModuleManager.enableModule, (address(module))), Enum.Operation.Call
        );

        guard = new SafeFirewallGuardHarness(_config());
        _installGuard(address(guard));
    }

    // ---------------------------------------------------------------- setup helpers

    function _config() internal view returns (ISafeFirewallGuard.FirewallConfig memory) {
        return ISafeFirewallGuard.FirewallConfig({
            safe: address(safe), multiSendCallOnly: infra.multiSendCallOnly, permit2: infra.permit2
        });
    }

    function _createOwners() private {
        for (uint256 i = 0; i < OWNER_COUNT; i++) {
            (address owner, uint256 key) = makeAddrAndKey(string.concat("owner", vm.toString(i)));
            owners.push(owner);
            ownerKey[owner] = key;
        }
        // Safe requires signatures ordered by ascending owner address (Safe.sol:338).
        for (uint256 i = 1; i < owners.length; i++) {
            for (uint256 j = i; j > 0 && owners[j - 1] > owners[j]; j--) {
                (owners[j - 1], owners[j]) = (owners[j], owners[j - 1]);
            }
        }
    }

    function _createSafe() private returns (ISafe) {
        bytes memory initializer = abi.encodeCall(
            ISafe.setup, (owners, THRESHOLD, address(0), "", infra.fallbackHandler, address(0), 0, payable(address(0)))
        );
        return ISafe(
            payable(address(
                    SafeProxyFactory(infra.proxyFactory)
                        .createProxyWithNonce(infra.singleton, initializer, SAFE_SALT_NONCE)
                ))
        );
    }

    /// @dev Install order with no guard active yet: module guard first, then transaction guard, so
    ///      neither transaction is checked by the guard being installed.
    function _installGuard(address g) internal {
        _execSigned(address(safe), 0, abi.encodeCall(IModuleManager.setModuleGuard, (g)), Enum.Operation.Call);
        _execSigned(address(safe), 0, abi.encodeCall(IGuardManager.setGuard, (g)), Enum.Operation.Call);
    }

    // ---------------------------------------------------------------- signing and execution

    function _sign(bytes32 txHash) internal view returns (bytes memory signatures) {
        for (uint256 i = 0; i < THRESHOLD; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey[owners[i]], txHash);
            signatures = abi.encodePacked(signatures, r, s, v);
        }
    }

    function _txHash(address to, uint256 value, bytes memory data, Enum.Operation op, uint256 safeTxGas, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        return safe.getTransactionHash(to, value, data, op, safeTxGas, 0, 0, address(0), address(0), nonce);
    }

    /// @notice Calldata for `safe.execTransaction`, signed for `nonce`. Used for nested or batched
    ///         execution from helper contracts.
    function _signedExecCalldata(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        uint256 safeTxGas,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes memory sigs = _sign(_txHash(to, value, data, op, safeTxGas, nonce));
        return abi.encodeCall(
            ISafe.execTransaction, (to, value, data, op, safeTxGas, 0, 0, address(0), payable(address(0)), sigs)
        );
    }

    function _execSigned(address to, uint256 value, bytes memory data, Enum.Operation op) internal returns (bool) {
        return _execSignedWithGas(to, value, data, op, 0);
    }

    function _execSignedWithGas(address to, uint256 value, bytes memory data, Enum.Operation op, uint256 safeTxGas)
        internal
        returns (bool)
    {
        bytes memory sigs = _sign(_txHash(to, value, data, op, safeTxGas, safe.nonce()));
        return safe.execTransaction(to, value, data, op, safeTxGas, 0, 0, address(0), payable(address(0)), sigs);
    }

    function _readSlotAddress(bytes32 slot) internal view returns (address) {
        return abi.decode(safe.getStorageAt(uint256(slot), 1), (address));
    }
}
