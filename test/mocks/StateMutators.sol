// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

/// @notice Unit-variant stand-in for the Bybit attacker contract (docs/bybit-incident.md §4). Its
///         only function is `transfer(address,uint256)`, and under delegatecall it writes its first
///         argument into slot 0, the Safe's singleton. The fork variant uses the real contract, and a
///         fidelity test checks that both behave the same.
contract BybitStyleDelegate {
    function transfer(address to, uint256) external {
        assembly ("memory-safe") {
            sstore(0, to)
        }
    }
}

/// @notice Delegatecalled by the Safe to write an arbitrary storage slot (I2.15, corruption tests).
contract SlotWriter {
    function write(bytes32 slot, bytes32 value) external {
        assembly ("memory-safe") {
            sstore(slot, value)
        }
    }
}

/// @notice Delegatecalls `target` with `data` in its own context and returns its own slot 0. Used to
///         compare the real Bybit delegate with `BybitStyleDelegate` (fork fidelity test).
contract DelegateProbe {
    function run(address target, bytes calldata data) external returns (bytes32 slot0) {
        (bool ok,) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        assembly ("memory-safe") {
            slot0 := sload(0)
        }
    }
}

/// @notice Holds the Safe's ORIGINAL values in its own storage, for `LyingSingleton` to serve.
/// @dev A separate contract is needed because the proxy delegatecalls the singleton: inside
///      `LyingSingleton`, storage reads hit the Safe's storage, not the liar's own.
contract OriginalsStore {
    mapping(uint256 slot => bytes32 value) public recorded;
    address[] internal originalOwners;
    address[] internal originalModules;
    uint256 public originalThreshold;

    constructor(
        uint256[] memory slots,
        bytes32[] memory values,
        address[] memory owners_,
        address[] memory modules_,
        uint256 threshold_
    ) {
        for (uint256 i = 0; i < slots.length; i++) {
            recorded[slots[i]] = values[i];
        }
        originalOwners = owners_;
        originalModules = modules_;
        originalThreshold = threshold_;
    }

    function owners() external view returns (address[] memory) {
        return originalOwners;
    }

    function modules() external view returns (address[] memory) {
        return originalModules;
    }
}

/// @notice A replacement singleton that lies: every getter the guard could use returns the Safe's
///         ORIGINAL values (I2.13). Only the proxy's own `masterCopy()` shortcut reveals the swap.
/// @dev Runs under delegatecall from the Safe proxy, so it keeps no storage of its own. It reads the
///      originals from `ORIGINALS` (an immutable, which lives in code) through external calls.
contract LyingSingleton {
    address internal constant SENTINEL = address(0x1);
    OriginalsStore public immutable ORIGINALS;

    constructor(OriginalsStore originals) {
        ORIGINALS = originals;
    }

    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes memory out) {
        out = new bytes(length * 32);
        for (uint256 i = 0; i < length; i++) {
            bytes32 v = ORIGINALS.recorded(offset + i);
            assembly ("memory-safe") {
                mstore(add(add(out, 0x20), mul(i, 0x20)), v)
            }
        }
    }

    function getOwners() external virtual returns (address[] memory) {
        return ORIGINALS.owners();
    }

    function getThreshold() external view returns (uint256) {
        return ORIGINALS.originalThreshold();
    }

    function getModulesPaginated(address, uint256) external view returns (address[] memory, address) {
        return (ORIGINALS.modules(), SENTINEL);
    }
}

/// @notice Originals plus a re-entry payload, for `ReentrantLyingSingleton`.
contract ReentrantOriginalsStore is OriginalsStore {
    address public immutable ORIGINAL_SINGLETON;
    bytes public reentry;

    constructor(
        uint256[] memory slots,
        bytes32[] memory values,
        address[] memory owners_,
        address[] memory modules_,
        uint256 threshold_,
        address originalSingleton,
        bytes memory reentry_
    ) OriginalsStore(slots, values, owners_, modules_, threshold_) {
        ORIGINAL_SINGLETON = originalSingleton;
        reentry = reentry_;
    }
}

/// @notice A lying singleton whose `getOwners()` tries to re-enter `execTransaction` before answering.
/// @dev It delegatecalls the ORIGINAL Safe singleton with a validly signed execTransaction, so real Safe
///      code runs in the Safe's storage. Under a STATICCALL that can't succeed: execTransaction's
///      `nonce++` is a storage write (Safe.sol:145). Any failure is bubbled unchanged.
contract ReentrantLyingSingleton is LyingSingleton {
    constructor(ReentrantOriginalsStore originals) LyingSingleton(originals) {}

    function getOwners() external override returns (address[] memory) {
        ReentrantOriginalsStore store = ReentrantOriginalsStore(address(ORIGINALS));
        (bool ok, bytes memory ret) = store.ORIGINAL_SINGLETON().delegatecall(store.reentry());
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return store.owners();
    }
}

/// @notice A lying singleton whose `getOwners()` writes the Safe's threshold slot directly (slot 4,
///         SafeStorage.sol:17) before answering. Only a STATICCALL context can stop this write. Nothing
///         else in the guard would see it, because the test guard compares only the owner list.
contract StateWritingLyingSingleton is LyingSingleton {
    constructor(OriginalsStore originals) LyingSingleton(originals) {}

    function getOwners() external override returns (address[] memory) {
        assembly ("memory-safe") {
            sstore(4, 1)
        }
        return ORIGINALS.owners();
    }
}

/// @notice An escape target whose answers can change while its code (and so its codehash) stays the
///         same. Used to test the execute-time I4.20 re-check on its own (ADR 0023).
contract MutableBindingGuard {
    address public SAFE;
    bool public supportsBoth = true;

    constructor(address safe_) {
        SAFE = safe_;
    }

    function setSafe(address safe_) external {
        SAFE = safe_;
    }

    function setSupportsBoth(bool v) external {
        supportsBoth = v;
    }

    function supportsInterface(bytes4) external view returns (bool) {
        return supportsBoth;
    }
}

/// @notice An escape target that passes the firewall's I4.20 checks but, when `refuseSafe` is set,
///         tells the Safe it is not a guard. The Safe's `setGuard` then reverts GS300
///         (GuardManager.sol:72), so `execTransaction` with a non-zero safeTxGas returns
///         success == false (Safe.sol:180-186). Used to test that a failed escape execution does
///         not consume its item (ADR 0023, D7).
contract SafeRefusingGuard {
    address public immutable SAFE;
    bool public refuseSafe;

    constructor(address safe_) {
        SAFE = safe_;
    }

    function setRefuseSafe(bool v) external {
        refuseSafe = v;
    }

    function supportsInterface(bytes4) external view returns (bool) {
        return !(refuseSafe && msg.sender == SAFE);
    }
}
