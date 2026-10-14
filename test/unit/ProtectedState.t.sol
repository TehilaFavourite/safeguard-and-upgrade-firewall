// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {IFallbackManager} from "safe-smart-account/contracts/interfaces/IFallbackManager.sol";
import {IGuardManager} from "safe-smart-account/contracts/interfaces/IGuardManager.sol";
import {IModuleManager} from "safe-smart-account/contracts/interfaces/IModuleManager.sol";
import {IOwnerManager} from "safe-smart-account/contracts/interfaces/IOwnerManager.sol";
import {Enum} from "safe-smart-account/contracts/libraries/Enum.sol";

import {ISafeFirewallGuard} from "../../src/interfaces/ISafeFirewallGuard.sol";
import {SafeSlots} from "../../src/libraries/SafeSlots.sol";
import {FirewallTestBase} from "../base/FirewallTestBase.sol";
import {LocalSafe} from "../base/LocalSafe.t.sol";
import {FeatureForkSafe} from "../base/ForkSafe.t.sol";
import {SafeFirewallGuardHarness} from "../harness/SafeFirewallGuardHarness.sol";
import {PostCheckOnlyGuard, CompareSpyGuard} from "../harness/SeamGuards.sol";
import {BybitStyleDelegate, SlotWriter, LyingSingleton, OriginalsStore} from "../mocks/StateMutators.sol";
import {Reverter} from "../mocks/Reverter.sol";
import {BybitPayload} from "../fixtures/BybitPayload.sol";

/// @dev Constants shared by the protected-state suites.
abstract contract ProtectedStateBase is FirewallTestBase {
    // lib/safe-smart-account/contracts/libraries/SafeStorage.sol:11 (singleton) and :17 (threshold)
    uint256 internal constant SINGLETON_SLOT = 0;
    uint256 internal constant THRESHOLD_SLOT = 4;
    // lib/safe-smart-account/contracts/base/FallbackManager.sol:13
    bytes32 internal constant FALLBACK_HANDLER_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    // ADR 0020
    uint256 internal constant MAX_MODULES = 16;
    // `masterCopy()`, answered by the proxy itself (SafeProxy.sol:45)
    bytes4 internal constant MASTER_COPY_SELECTOR = 0xa619486e;

    function _masterCopy() internal view returns (address singleton) {
        (bool ok, bytes memory ret) = address(safe).staticcall(abi.encodeWithSelector(MASTER_COPY_SELECTOR));
        require(ok, "masterCopy failed");
        singleton = abi.decode(ret, (address));
    }

    function _prepend(address first, address[] memory rest) internal pure returns (address[] memory out) {
        out = new address[](rest.length + 1);
        out[0] = first;
        for (uint256 i = 0; i < rest.length; i++) {
            out[i + 1] = rest[i];
        }
    }
}

/// @notice I2.12, I2.15 (valid setter changes), I2.16, I2.17 with the installed guard. In Phase 2 no
///         change to a protected field is authorized, so each of these self-calls must revert.
abstract contract ProtectedStateTest is ProtectedStateBase {
    function test_PostCheck_GuardSlotChangeReverts() public {
        address other = address(new SafeFirewallGuardHarness(_config()));
        _execSignedExpectRevert(
            address(safe),
            0,
            abi.encodeCall(IGuardManager.setGuard, (other)),
            Enum.Operation.Call,
            _changed(ISafeFirewallGuard.ProtectedField.GUARD, _b32(address(guard)), _b32(other))
        );
    }

    function test_PostCheck_ModuleGuardSlotChangeReverts() public {
        address other = address(new SafeFirewallGuardHarness(_config()));
        _execSignedExpectRevert(
            address(safe),
            0,
            abi.encodeCall(IModuleManager.setModuleGuard, (other)),
            Enum.Operation.Call,
            _changed(ISafeFirewallGuard.ProtectedField.MODULE_GUARD, _b32(address(guard)), _b32(other))
        );
    }

    function test_PostCheck_FallbackHandlerChangeReverts() public {
        address newHandler = makeAddr("newHandler");
        _execSignedExpectRevert(
            address(safe),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (newHandler)),
            Enum.Operation.Call,
            _changed(ISafeFirewallGuard.ProtectedField.FALLBACK_HANDLER, _b32(infra.fallbackHandler), _b32(newHandler))
        );
    }

    /// @dev The module linked list prepends (ModuleManager.sol:134-135).
    function test_PostCheck_ModuleListChangeReverts() public {
        address newModule = makeAddr("newModule");
        address[] memory beforeList = _modules();
        _execSignedExpectRevert(
            address(safe),
            0,
            abi.encodeCall(IModuleManager.enableModule, (newModule)),
            Enum.Operation.Call,
            _changed(
                ISafeFirewallGuard.ProtectedField.MODULES,
                _hashList(beforeList),
                _hashList(_prepend(newModule, beforeList))
            )
        );
    }

    /// @dev The owner linked list prepends (OwnerManager.sol addOwnerWithThreshold). Threshold unchanged.
    function test_PostCheck_OwnersChangeReverts() public {
        address newOwner = makeAddr("newOwner");
        address[] memory beforeList = safe.getOwners();
        _execSignedExpectRevert(
            address(safe),
            0,
            abi.encodeCall(IOwnerManager.addOwnerWithThreshold, (newOwner, THRESHOLD)),
            Enum.Operation.Call,
            _changed(
                ISafeFirewallGuard.ProtectedField.OWNERS,
                _hashList(beforeList),
                _hashList(_prepend(newOwner, beforeList))
            )
        );
    }

    function test_PostCheck_ThresholdChangeReverts() public {
        _execSignedExpectRevert(
            address(safe),
            0,
            abi.encodeCall(IOwnerManager.changeThreshold, (1)),
            Enum.Operation.Call,
            _changed(ISafeFirewallGuard.ProtectedField.THRESHOLD, bytes32(THRESHOLD), bytes32(uint256(1)))
        );
    }

    /// @dev I2.16: the module path gets the same comparison (ModuleManager.sol:101, 120).
    function test_PostCheck_ModulePathFallbackHandlerChangeReverts() public {
        address newHandler = makeAddr("newHandler");
        vm.expectRevert(
            _changed(ISafeFirewallGuard.ProtectedField.FALLBACK_HANDLER, _b32(infra.fallbackHandler), _b32(newHandler))
        );
        module.exec(
            safe,
            address(safe),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (newHandler)),
            Enum.Operation.Call
        );
    }

    /// @dev Regression: an execution that changes no protected field passes.
    function test_PostCheck_NoProtectedChangePasses() public {
        address recipient = makeAddr("recipient");
        assertTrue(_execSigned(recipient, 1 wei, "", Enum.Operation.Call));
    }

    /// @dev I2.17: the guard's slot constants equal the installed Safe source and the live layout.
    function test_SafeSlots_ConstantsMatchSafeSource() public view {
        assertEq(SafeSlots.SINGLETON_SLOT, SINGLETON_SLOT, "singleton slot");
        assertEq(SafeSlots.GUARD_SLOT, GUARD_STORAGE_SLOT, "guard slot");
        assertEq(SafeSlots.MODULE_GUARD_SLOT, MODULE_GUARD_STORAGE_SLOT, "module guard slot");
        assertEq(SafeSlots.FALLBACK_HANDLER_SLOT, FALLBACK_HANDLER_SLOT, "fallback handler slot");
        assertEq(SafeSlots.THRESHOLD_SLOT, THRESHOLD_SLOT, "threshold slot");
        assertEq(SafeSlots.MAX_MODULES, MAX_MODULES, "max modules");

        // Live layout: each slot holds the value set through the real setters during setUp.
        assertEq(_readSlotAddress(bytes32(SafeSlots.SINGLETON_SLOT)), infra.singleton, "live singleton");
        assertEq(_readSlotAddress(SafeSlots.GUARD_SLOT), address(guard), "live guard");
        assertEq(_readSlotAddress(SafeSlots.MODULE_GUARD_SLOT), address(guard), "live module guard");
        assertEq(_readSlotAddress(SafeSlots.FALLBACK_HANDLER_SLOT), infra.fallbackHandler, "live fallback handler");
        assertEq(abi.decode(safe.getStorageAt(SafeSlots.THRESHOLD_SLOT, 1), (uint256)), THRESHOLD, "live threshold");
    }
}

/// @notice I2.13, I2.15 (raw writes), fail-closed corruption: the operation policy is disabled, so a
///         delegatecall can write Safe storage and only the post-check stands in the way.
abstract contract ProtectedStatePostOnlyTest is ProtectedStateBase {
    SlotWriter internal writer;

    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        virtual
        override
        returns (SafeFirewallGuardHarness)
    {
        return new PostCheckOnlyGuard(config);
    }

    function setUp() public virtual override {
        super.setUp();
        writer = new SlotWriter();
    }

    function _write(bytes32 slot, bytes32 value) internal pure returns (bytes memory) {
        return abi.encodeCall(SlotWriter.write, (slot, value));
    }

    /// @dev I2.15: a raw write to any scalar protected slot is caught, with exact before and after values.
    function testFuzz_PostCheck_RawScalarSlotWriteReverts(uint8 which, uint160 raw) public {
        which = uint8(bound(which, 0, 4));
        bytes32 slot;
        ISafeFirewallGuard.ProtectedField field;
        bytes32 beforeValue;
        if (which == 0) {
            (slot, field, beforeValue) =
            (bytes32(SINGLETON_SLOT), ISafeFirewallGuard.ProtectedField.SINGLETON, _b32(infra.singleton));
        } else if (which == 1) {
            (slot, field, beforeValue) =
            (GUARD_STORAGE_SLOT, ISafeFirewallGuard.ProtectedField.GUARD, _b32(address(guard)));
        } else if (which == 2) {
            (slot, field, beforeValue) =
            (MODULE_GUARD_STORAGE_SLOT, ISafeFirewallGuard.ProtectedField.MODULE_GUARD, _b32(address(guard)));
        } else if (which == 3) {
            (slot, field, beforeValue) =
            (FALLBACK_HANDLER_SLOT, ISafeFirewallGuard.ProtectedField.FALLBACK_HANDLER, _b32(infra.fallbackHandler));
        } else {
            (slot, field, beforeValue) =
            (bytes32(THRESHOLD_SLOT), ISafeFirewallGuard.ProtectedField.THRESHOLD, bytes32(THRESHOLD));
        }
        bytes32 afterValue = bytes32(uint256(raw));
        vm.assume(afterValue != beforeValue);

        _execSignedExpectRevert(
            address(writer),
            0,
            _write(slot, afterValue),
            Enum.Operation.DelegateCall,
            _changed(field, beforeValue, afterValue)
        );
    }

    // ---------------------------------------------------------------- linked-list corruption (ADR 0020)
    // Mapping slots: modules at storage slot 1 and owners at slot 2 (SafeStorage.sol:13, :15).

    function _moduleEntry(address key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, uint256(1)));
    }

    function _ownerEntry(address key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, uint256(2)));
    }

    /// @dev What the Safe's own getOwners() reverts with when the owner list is unterminated. It runs
    ///      past the end of its array (OwnerManager.sol:135-144), and the result differs by compiler,
    ///      so each variant supplies it.
    function _unterminatedOwnersRevertData() internal pure virtual returns (bytes memory);

    function _signedWriterTx(bytes32 slot, bytes32 value) internal view returns (bytes memory data, bytes memory sigs) {
        data = _write(slot, value);
        sigs = _sign(_txHash(address(writer), 0, data, Enum.Operation.DelegateCall, 0, safe.nonce()));
    }

    function _execWriter(bytes memory data, bytes memory sigs) internal returns (bool) {
        return safe.execTransaction(
            address(writer), 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), sigs
        );
    }

    /// @dev A cycle (modules[module] = module). The read is bounded at MAX_MODULES + 1 entries, so it
    ///      reverts TooManyModules rather than running out of gas.
    function test_PostCheck_ModuleListCycleRevertsTooManyModules() public {
        (bytes memory data, bytes memory sigs) = _signedWriterTx(_moduleEntry(address(module)), _b32(address(module)));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.TooManyModules.selector, MAX_MODULES));
        _execWriter(data, sigs);
    }

    /// @dev Control: the same transaction writing the entry's current value (SENTINEL) succeeds.
    function test_PostCheck_ModuleListCycleControlPasses() public {
        (bytes memory data, bytes memory sigs) = _signedWriterTx(_moduleEntry(address(module)), _b32(SENTINEL_MODULES));
        assertTrue(_execWriter(data, sigs));
    }

    /// @dev Not terminated by the sentinel (modules[module] = 0). The Safe's loop stops at address(0),
    ///      and returns the last entry as `next` (ModuleManager.sol:212, 226-227).
    function test_PostCheck_ModuleListUnterminatedReverts() public {
        (bytes memory data, bytes memory sigs) = _signedWriterTx(_moduleEntry(address(module)), bytes32(0));
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.ModuleListNotTerminated.selector, address(module)));
        _execWriter(data, sigs);
    }

    /// @dev Control for the unterminated case: same slot, current value.
    function test_PostCheck_ModuleListUnterminatedControlPasses() public {
        (bytes memory data, bytes memory sigs) = _signedWriterTx(_moduleEntry(address(module)), _b32(SENTINEL_MODULES));
        assertTrue(_execWriter(data, sigs));
    }

    /// @dev Unterminated owner list (owners[lastOwner] = 0): the Safe's own getOwners() reverts, with
    ///      exact revert data per variant.
    function test_PostCheck_OwnerListUnterminatedReverts() public {
        address[] memory list = safe.getOwners();
        (bytes memory data, bytes memory sigs) = _signedWriterTx(_ownerEntry(list[list.length - 1]), bytes32(0));
        vm.expectRevert(_unterminatedOwnersRevertData());
        _execWriter(data, sigs);
    }

    /// @dev Control: same slot, current value (SENTINEL_OWNERS = address(0x1), OwnerManager.sol:17).
    function test_PostCheck_OwnerListControlPasses() public {
        address[] memory list = safe.getOwners();
        (bytes memory data, bytes memory sigs) = _signedWriterTx(_ownerEntry(list[list.length - 1]), _b32(address(0x1)));
        assertTrue(_execWriter(data, sigs));
    }

    // ---------------------------------------------------------------- I2.13 lying singleton

    function _lyingSingleton() internal returns (LyingSingleton) {
        uint256[] memory slots = new uint256[](5);
        bytes32[] memory values = new bytes32[](5);
        (slots[0], values[0]) = (SINGLETON_SLOT, _b32(infra.singleton));
        (slots[1], values[1]) = (uint256(GUARD_STORAGE_SLOT), _b32(address(guard)));
        (slots[2], values[2]) = (uint256(MODULE_GUARD_STORAGE_SLOT), _b32(address(guard)));
        (slots[3], values[3]) = (uint256(FALLBACK_HANDLER_SLOT), _b32(infra.fallbackHandler));
        (slots[4], values[4]) = (THRESHOLD_SLOT, bytes32(THRESHOLD));
        return new LyingSingleton(new OriginalsStore(slots, values, safe.getOwners(), _modules(), safe.getThreshold()));
    }

    /// @dev Control: with the lying singleton in slot 0, EVERY getter the guard could use returns the
    ///      ORIGINAL values. Only the proxy's `masterCopy()` reveals the swap. This is what makes I2.13
    ///      meaningful.
    function test_LyingSingleton_GettersReturnOriginalsOnlyMasterCopyDiffers() public {
        address[] memory ownersBefore = safe.getOwners();
        address[] memory modulesBefore = _modules();
        LyingSingleton liar = _lyingSingleton();

        vm.store(address(safe), bytes32(SINGLETON_SLOT), _b32(address(liar)));

        assertEq(_masterCopy(), address(liar), "masterCopy must reveal the swap");
        assertEq(_readSlotAddress(bytes32(SINGLETON_SLOT)), infra.singleton, "getStorageAt(0) lies");
        assertEq(_readSlotAddress(GUARD_STORAGE_SLOT), address(guard), "getStorageAt(guard) lies");
        assertEq(_readSlotAddress(MODULE_GUARD_STORAGE_SLOT), address(guard), "getStorageAt(module guard) lies");
        assertEq(_readSlotAddress(FALLBACK_HANDLER_SLOT), infra.fallbackHandler, "getStorageAt(fallback) lies");
        assertEq(safe.getThreshold(), THRESHOLD, "getThreshold lies");
        assertEq(_hashList(safe.getOwners()), _hashList(ownersBefore), "getOwners lies");
        assertEq(_hashList(_modules()), _hashList(modulesBefore), "getModulesPaginated lies");
    }

    /// @dev I2.13: a Bybit-shaped payload installs the lying singleton. The post-check still reverts on
    ///      SINGLETON, because it reads the singleton through masterCopy() first.
    function test_PostCheck_LyingSingletonCaughtViaMasterCopy() public {
        LyingSingleton liar = _lyingSingleton();
        address delegate = address(new BybitStyleDelegate());
        _execSignedExpectRevert(
            delegate,
            0,
            BybitPayload.dataWithSingleton(address(liar)),
            Enum.Operation.DelegateCall,
            _changed(ISafeFirewallGuard.ProtectedField.SINGLETON, _b32(infra.singleton), _b32(address(liar)))
        );
        assertEq(_masterCopy(), infra.singleton, "slot 0 must be restored by the revert");
    }
}

/// @notice I2.14: the comparison runs even when the inner call failed (success == false), on both paths.
abstract contract CompareRunsOnFailureTest is ProtectedStateBase {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        virtual
        override
        returns (SafeFirewallGuardHarness)
    {
        return new CompareSpyGuard(config);
    }

    /// @dev safeTxGas != 0, so the failing inner call returns success == false (Safe.sol:184) and the
    ///      post-check runs (Safe.sol:203-204).
    function test_PostCheck_RunsWhenSignedInnerCallFails() public {
        address reverter = address(new Reverter());
        SafeTx memory t = _safeTx(reverter, 0, "", Enum.Operation.Call);
        t.safeTxGas = NON_ZERO_SAFE_TX_GAS;
        _execTxExpectRevert(t, abi.encodeWithSelector(CompareSpyGuard.CompareRan.selector));
    }

    /// @dev The module path returns success == false for a failing inner call, then runs the post-hook
    ///      (ModuleManager.sol:161-162).
    function test_PostCheck_RunsWhenModuleInnerCallFails() public {
        address reverter = address(new Reverter());
        vm.expectRevert(abi.encodeWithSelector(CompareSpyGuard.CompareRan.selector));
        module.exec(safe, reverter, 0, "", Enum.Operation.Call);
    }
}

/// @notice I2.18 at the boundary: exactly MAX_MODULES modules is allowed.
abstract contract ModuleLimitAtMaxTest is ProtectedStateBase {
    function _beforeGuardInstall() internal virtual override {
        // setUp already enabled `module`; add MAX_MODULES - 1 more.
        for (uint256 i = 1; i < MAX_MODULES; i++) {
            _execSigned(
                address(safe),
                0,
                // forge-lint: disable-next-line(unsafe-typecast)
                abi.encodeCall(IModuleManager.enableModule, (address(uint160(0x10000 + i)))), // i <= 16: no truncation
                Enum.Operation.Call
            );
        }
    }

    function test_ModuleLimit_AtMaxPasses() public {
        assertEq(_modules().length, MAX_MODULES);
        assertTrue(_execSigned(makeAddr("recipient"), 1 wei, "", Enum.Operation.Call));
    }
}

/// @notice I2.18 over the boundary, plus the D3 liveness note: R2 still passes.
abstract contract ModuleLimitOverMaxTest is ProtectedStateBase {
    function _beforeGuardInstall() internal virtual override {
        for (uint256 i = 1; i <= MAX_MODULES; i++) {
            _execSigned(
                address(safe),
                0,
                // forge-lint: disable-next-line(unsafe-typecast)
                abi.encodeCall(IModuleManager.enableModule, (address(uint160(0x10000 + i)))), // i <= 16: no truncation
                Enum.Operation.Call
            );
        }
    }

    function test_ModuleLimit_OverMaxSignedReverts() public {
        assertEq(_modules().length, MAX_MODULES + 1);
        _execSignedExpectRevert(
            makeAddr("recipient"),
            1 wei,
            "",
            Enum.Operation.Call,
            abi.encodeWithSelector(ISafeFirewallGuard.TooManyModules.selector, MAX_MODULES)
        );
    }

    function test_ModuleLimit_OverMaxModulePathReverts() public {
        address recipient = makeAddr("recipient");
        vm.expectRevert(abi.encodeWithSelector(ISafeFirewallGuard.TooManyModules.selector, MAX_MODULES));
        module.exec(safe, recipient, 1 wei, "", Enum.Operation.Call);
    }

    /// @dev D3 / threat model: cancellation returns before the module read, so a Safe over the
    ///      limit is never permanently frozen.
    function test_ModuleLimit_CancellationStillPassesOverMax() public {
        uint256 n = safe.nonce();
        assertTrue(_execTx(_safeTx(address(safe), 0, "", Enum.Operation.Call)));
        assertEq(safe.nonce(), n + 1);
    }
}

contract ProtectedStateUnitTest is ProtectedStateTest, LocalSafe {}

/// forge-config: default.fuzz.runs = 64
contract ProtectedStateForkTest is ProtectedStateTest, FeatureForkSafe {}

contract ProtectedStatePostOnlyUnitTest is ProtectedStatePostOnlyTest, LocalSafe {
    /// @dev Local 0.8.28 build: out-of-bounds array write -> Panic(0x32).
    function _unterminatedOwnersRevertData() internal pure override returns (bytes memory) {
        return abi.encodeWithSignature("Panic(uint256)", uint256(0x32));
    }

    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(ProtectedStatePostOnlyTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return ProtectedStatePostOnlyTest._newGuard(config);
    }

    function setUp() public override(ProtectedStatePostOnlyTest, FirewallTestBase) {
        ProtectedStatePostOnlyTest.setUp();
    }
}

/// forge-config: default.fuzz.runs = 64
contract ProtectedStatePostOnlyForkTest is ProtectedStatePostOnlyTest, FeatureForkSafe {
    /// @dev Mainnet singleton, built with solc 0.7.6: out-of-bounds access hits the `invalid` opcode,
    ///      which reverts with empty data.
    function _unterminatedOwnersRevertData() internal pure override returns (bytes memory) {
        return "";
    }

    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(ProtectedStatePostOnlyTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return ProtectedStatePostOnlyTest._newGuard(config);
    }

    function setUp() public override(ProtectedStatePostOnlyTest, FirewallTestBase) {
        ProtectedStatePostOnlyTest.setUp();
    }
}

contract CompareRunsOnFailureUnitTest is CompareRunsOnFailureTest, LocalSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(CompareRunsOnFailureTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return CompareRunsOnFailureTest._newGuard(config);
    }
}

/// forge-config: default.fuzz.runs = 64
contract CompareRunsOnFailureForkTest is CompareRunsOnFailureTest, FeatureForkSafe {
    function _newGuard(ISafeFirewallGuard.FirewallConfig memory config)
        internal
        override(CompareRunsOnFailureTest, FirewallTestBase)
        returns (SafeFirewallGuardHarness)
    {
        return CompareRunsOnFailureTest._newGuard(config);
    }
}

contract ModuleLimitAtMaxUnitTest is ModuleLimitAtMaxTest, LocalSafe {
    function _beforeGuardInstall() internal override(ModuleLimitAtMaxTest, FirewallTestBase) {
        ModuleLimitAtMaxTest._beforeGuardInstall();
    }
}

/// forge-config: default.fuzz.runs = 64
contract ModuleLimitAtMaxForkTest is ModuleLimitAtMaxTest, FeatureForkSafe {
    function _beforeGuardInstall() internal override(ModuleLimitAtMaxTest, FirewallTestBase) {
        ModuleLimitAtMaxTest._beforeGuardInstall();
    }
}

contract ModuleLimitOverMaxUnitTest is ModuleLimitOverMaxTest, LocalSafe {
    function _beforeGuardInstall() internal override(ModuleLimitOverMaxTest, FirewallTestBase) {
        ModuleLimitOverMaxTest._beforeGuardInstall();
    }
}

/// forge-config: default.fuzz.runs = 64
contract ModuleLimitOverMaxForkTest is ModuleLimitOverMaxTest, FeatureForkSafe {
    function _beforeGuardInstall() internal override(ModuleLimitOverMaxTest, FirewallTestBase) {
        ModuleLimitOverMaxTest._beforeGuardInstall();
    }
}
