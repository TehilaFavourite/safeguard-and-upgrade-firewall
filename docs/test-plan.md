# Test Plan (v1)

This plan maps every requirement in `docs/v1-spec.md` and every mitigation in
`docs/threat-model.md` to planned tests.

## Conventions

- **Variants.** Every test is written once against `FirewallTestBase` and runs in two variants
  (ADR 0013):
  - `*UnitTest`: the local 0.8.28 Safe build;
  - `*ForkTest`: the mainnet v1.5.0 singleton at a pinned block.

  Tests marked **(fork only)** need mainnet state.
- **Names:**

  | Kind | Pattern |
  |---|---|
  | Unit | `test_<Area>_<Behaviour>` |
  | Fuzz | `testFuzz_<Area>_<Behaviour>` |
  | Stateful | `invariant_<Property>` |
- **Statuses:**

  | Status | Meaning |
  |---|---|
  | ⏸ | Blocked on an open v1 item; the test exists in the plan but its expected behaviour is not decided yet |
  | ⚠️ | No on-chain test is possible. Covered by a characterization test, process or trust assumption, as stated |

## Phase 1: skeleton, harness, hook prefix

| ID | Requirement | Source | Tests |
|---|---|---|---|
| H1 | All four hooks revert unless `msg.sender == SAFE` | spec Hooks; ADR 0007; I1.1 | `testFuzz_Hooks_CheckTransactionRevertsForNonSafe`, `testFuzz_Hooks_CheckAfterExecutionRevertsForNonSafe`, `testFuzz_Hooks_CheckModuleTransactionRevertsForNonSafe`, `testFuzz_Hooks_CheckAfterModuleExecutionRevertsForNonSafe` |
| H2 | Reentrancy flag shared by all four hooks | ADR 0005 | `test_Reentrancy_NestedExecTransactionReverts`, `test_Reentrancy_ModuleTxInsideSignedTxReverts`, `test_Reentrancy_SignedTxInsideModuleTxReverts` |
| H3 | Flag cleared after every outcome | ADR 0005, 0014 | `test_Reentrancy_TwoSequentialExecutionsInOneTxPass`, `test_Reentrancy_FlagNotStuckAfterBlockedTx`, `test_Reentrancy_FlagNotStuckAfterInnerCallFailure` |
| H4 | Path flag recorded (signed, module, none) | ADR 0007; I1.8 | `test_Path_SignedPathRecorded`, `test_Path_ModulePathRecorded`, `test_Path_NoneOutsideExecution` |
| H5 | ERC-165 for both guard interfaces; the Safe accepts the guard in both slots | ADR 0001; I1.2, I1.3 | `test_ERC165_SupportsTransactionGuard`, `test_ERC165_SupportsModuleGuard`, `test_ERC165_SupportsIERC165`, `test_ERC165_RejectsInvalidId`, `testFuzz_ERC165_RejectsOtherIds`, `test_Install_SetGuardAndSetModuleGuardAccepted` |
| H6 | Factory: permissionless and idempotent; the address commits to (safe, version, constructor args) | ADR 0007; I1.5 | `testFuzz_Factory_AnyoneCanDeploy`, `test_Factory_DeploysAtPredictedAddress`, `testFuzz_Factory_DifferentConfigDifferentAddress`, `test_Factory_GuardBoundToSafe`, `test_Factory_EmitsGuardDeployed`, `test_Factory_DeployFromSafeTransaction`, `test_Factory_DeployTwiceReturnsSameAddress`, `test_Factory_SecondDeployEmitsNothing`, `test_Factory_ThirdPartyPreDeployDoesNotBreakSafeDeploy`. Phase 9: `test_InstallBatch_SucceedsAfterThirdPartyPreDeploy` |
| H7 | Canonical addresses are constructor immutables | ADR 0013; I1.4 | `test_Constructor_StoresCanonicalAddresses`, `test_Constructor_RevertsOnZeroSafe`, `test_Constructor_RevertsOnZeroMultiSendCallOnly`, `test_Constructor_RevertsOnZeroPermit2` |
| H7b | Fork variant: real mainnet code; skips visibly without RPC | ADR 0013; I1.10 | `test_ForkInfra_CanonicalContractsHaveCode`, `test_ForkInfra_ProxyRunsSafeV150` (fork only) |
| H7c | Phase 1 skeleton allows ordinary calls (scaffolding, deleted in Phase 2) | I1.11 | `test_Skeleton_AllowsOrdinaryCall` |
| H8 | Deploy script verifies `extcodehash` of canonical addresses | ADR 0013 | `test_DeployScript_RevertsOnCodehashMismatch` (fork only), `test_DeployScript_SucceedsOnMainnetAddresses` (fork only) |
| H9 | Hook order: refund check before R1 and R2 | ADR 0014 | `test_HookOrder_EscapeTxWithRefundFieldsReverts`, `test_HookOrder_CancellationWithRefundFieldsReverts` |
| H10 | Post-hook reverts unless a matching pre-hook is active on the same path (defence in depth) | ADR 0018; I1.9 | `test_PostHook_SignedWithoutPreHookReverts`, `test_PostHook_ModuleWithoutPreHookReverts`, `test_PostHook_PathMismatchReverts` |
| H11 | `to == GUARD` rejected except config and escape selectors; hook selectors always rejected | ADR 0018; I1.12 | Phase 1 (top-level, every selector): `test_GuardCall_SignedHookSelectorsRevert`, `testFuzz_GuardCall_SignedAnySelectorReverts`, `test_GuardCall_SignedEmptyCalldataReverts`, `test_GuardCall_SignedDelegatecallToGuardReverts`, `test_GuardCall_ModuleCallReverts`. Phase 3: `test_Batch_InnerCallToGuardHookReverts`. Phase 4: `test_GuardCall_PermittedSelectorListMatchesConfigAbi`, `test_Config_GuardNeverAllowlistable` |

## Phase 2: Bybit stopper

| ID | Requirement | Source | Tests |
|---|---|---|---|
| B1 | Signed-path delegatecall only to the pinned `MultiSendCallOnly` | spec pipeline 2; ADR 0003 | `test_Delegatecall_PinnedMultiSendCallOnlyAllowed`, `test_Delegatecall_ArbitraryTargetReverts`, `test_Delegatecall_PlainMultiSendReverts`, `testFuzz_Delegatecall_AnyOtherTargetReverts` |
| B2 | Module path never delegatecalls | spec pipeline 2; threat model §3.3 | `test_ModulePath_DelegatecallToMultiSendCallOnlyReverts`, `testFuzz_ModulePath_AnyDelegatecallReverts` |
| B3 | Refund fields must be zero on every signed transaction | ADR 0010 | `test_Refunds_GasPriceNonZeroReverts`, `test_Refunds_GasTokenNonZeroReverts`, `test_Refunds_RefundReceiverNonZeroReverts`, `testFuzz_Refunds_AnyNonZeroFieldReverts` |
| B4 | R2: the exact cancellation always passes | threat model R2 | `test_Cancellation_PassesUnderHostileConfig` (all caps 0, empty allowlist), `test_Cancellation_ConsumesNonceAndKillsBlockedTx` |
| B5 | R2 matches the exact shape only | threat model R2 | `test_Cancellation_WithValueGoesThroughPipeline`, `test_Cancellation_WithDataGoesThroughPipeline`, `test_Cancellation_DelegatecallGoesThroughPipeline` |
| B6 | The pre-check alone stops the Bybit payload | build plan Phase 2 | `test_Bybit_PreCheckAloneBlocksPayload`. The harness disables the post-check comparison through a test-only subclass |
| B7 | The post-check alone stops the Bybit payload | build plan Phase 2; ADR 0001 | `test_Bybit_PostCheckAloneBlocksPayload`. The harness allowlists the malicious target as a delegatecall target, so only the slot compare can stop it |
| B8 | Snapshot and compare every protected slot | spec Post-check | `test_PostCheck_SingletonChangeReverts`, `test_PostCheck_GuardSlotChangeReverts`, `test_PostCheck_ModuleGuardSlotChangeReverts`, `test_PostCheck_FallbackHandlerChangeReverts`, `test_PostCheck_ModuleListChangeReverts`, `test_PostCheck_OwnersChangeReverts`, `test_PostCheck_ThresholdChangeReverts`, `testFuzz_PostCheck_AnyProtectedSlotWriteReverts` |
| B9 | Slot constants match the Safe source | engineering standard | `test_SafeSlots_ConstantsMatchSafeSource`. Each constant is compared with `getStorageAt` on a Safe after a known setter call |
| B10 | Module-path post-check uses the cached module guard | ADR 0001 | `test_ModulePath_PostCheckCatchesModuleGuardSlotOverwrite` |

## Phase 3: MultiSend decoder

| ID | Requirement | Source | Tests |
|---|---|---|---|
| D1 | `to == 0` is normalized to the Safe before policy runs | ADR 0003 | `test_Decoder_ZeroToNormalizedToSafe`, `test_Batch_ZeroToSelfCallSubjectToSelfCallPolicy` |
| D2 | Strict tiling and bounds | ADR 0003 | `test_Decoder_TrailingBytesUpTo32Reverts`, `test_Decoder_TrailingBytesOver32Reverts`, `test_Decoder_DataLengthPastBufferReverts`, `test_Decoder_TruncatedEntryHeaderReverts` |
| D3 | Operation byte must be 0 | ADR 0003 | `testFuzz_Decoder_NonZeroOperationReverts` (1–255) |
| D4 | Canonical ABI wrapper | ADR 0003 | `test_Decoder_WrongSelectorReverts`, `test_Decoder_NonCanonicalOffsetReverts`, `test_Decoder_LengthInconsistentWithCalldataReverts` |
| D5 | Malformed input is never accepted | ADR 0003 | `testFuzz_Decoder_RandomBytesNeverAcceptedUnlessWellFormed` |
| D6 | Differential: an accepted batch is executed identically by `MultiSendCallOnly` | build plan Phase 3 | `testFuzz_Decoder_DifferentialWithMultiSendCallOnly`. A recording target logs every call `(to, value, data)` and is compared with the decoder's output |
| D7 | Every inner call runs the full pipeline | ADR 0003 | `test_Batch_OneViolatingInnerCallRevertsBatch`, `test_Batch_InnerDelegatecallImpossible` |
| D8 | Empty batch rejected | ADR 0003 (P2) | `test_Decoder_EmptyBatchReverts` |

## Phase 4: timelock, config, escape path, guardian

| ID | Requirement | Source | Tests |
|---|---|---|---|
| T1 | Queue → execute after delay; expiry 14 days after ETA | spec Config; ADR 0011 | `test_Timelock_ExecuteBeforeEtaReverts`, `test_Timelock_ExecuteAtEtaSucceeds`, `test_Timelock_ExecuteAfterExpiryReverts`, `test_Timelock_ExecuteTwiceReverts`, `test_Timelock_CancelledItemCannotExecute`, `testFuzz_Timelock_EtaAndExpiryBoundaries` |
| T2 | Delay classes and immutability | ADR 0011 | `test_Delays_ConfigIs48h`, `test_Delays_EscapeIs72h`, `test_Delays_GuardianChangeIs48h`, `test_Delays_NoSetterExists` |
| T3 | Config calls: signed path only | ADR 0007, 0014 | `test_ModulePath_QueueRejected`, `test_ModulePath_ExecuteRejected`, `test_ModulePath_CancelRejected`, `test_Config_DirectCallFromNonSafeReverts` |
| T4 | R1 escape shape (ADR 0014) | ADR 0014 | `test_Escape_QueueEscapeFastPathed`, `test_Escape_InsideBatchNotFastPathed`, `test_Escape_WithValueNotFastPathed`, `test_Escape_DelegatecallNotFastPathed`, `test_Escape_SetGuardWithoutMaturedItemReverts`, `test_Escape_SetGuardToDifferentAddressReverts`, `test_Escape_ExpiredItemReverts`, `test_Escape_ReplacementCodehashMismatchReverts`, `test_Escape_ReplacementWithoutCodeReverts`, `test_Escape_ReplacementDeployedByThirdPartyAccepted` |
| T5 | R1 survives a broken policy | threat model R1 | `test_Escape_QueueAndExecuteSucceedWhenPolicyAlwaysReverts`. A test-only subclass makes the pipeline revert on everything |
| T6 | R1 rejected on the module path | ADR 0014 | `test_ModulePath_QueueEscapeRejected`, `test_ModulePath_SetGuardWithMaturedItemRejected` |
| T7 | R1 fast return clears transient state | ADR 0014 | `test_Escape_FastReturnClearsTransientState` |
| T8 | Replacement order enforced: `setModuleGuard(x)` then `setGuard(x)` | ADR 0014 | `test_Escape_SetModuleGuardThenSetGuardSucceeds`, `test_Escape_SetGuardBeforeModuleGuardReverts`, `test_Escape_SetGuardWithModuleGuardNotXReverts`, `test_Escape_ItemMarkedUsedOnSetGuard`, `test_Escape_UsedItemCannotBeReplayed`, `test_Escape_NoUnguardedWindowDuringReplacement`, `test_Escape_CancelAfterModuleGuardStepLeavesModuleGuardX` |
| T9 | Guardian cancel rights | ADR 0008 | `test_Guardian_CancelsConfigItem`, `test_Guardian_CannotCancelEscapeItem`, `test_Guardian_CannotCancelGuardianRemoval`, `test_Guardian_CannotQueue`, `test_Guardian_CannotExecute`, `test_Guardian_NonGuardianCannotCancel` |
| T10 | Signers can cancel everything, including escape items | ADR 0008 | `test_SignerCancel_CancelsEscapeItemViaR1`, `test_SignerCancel_CancelsGuardianRemoval` |
| T11 | Power-reducing change cancels pending power-adding changes for the same key | spec Opposite pending; ADR 0011, 0012 | `test_P1_CapLowerCancelsPendingRaise`, `test_P1_WithdrawalRaiseCancelsPendingLowering`, `test_P1_OtherKeysUnaffected` |
| T12 | Events for queue, execute, cancel and expiry | engineering standard | `test_Events_Queued`, `test_Events_Executed`, `test_Events_Cancelled`, `test_Events_CancelledByGuardian`, `test_Events_Expired` |

## Phase 5: self-call policy and module parity

| ID | Requirement | Source | Tests |
|---|---|---|---|
| S1 | Timelocked self-calls only as matured items | ADR 0016 | Per function: `test_SelfCall_<Fn>_RevertsWithoutItem` and `test_SelfCall_<Fn>_SucceedsWithMaturedItem`, for `EnableModule`, `SetFallbackHandler`, `ChangeThresholdRaise`, `ChangeThresholdLower`, `AddOwnerWithThreshold`, `RemoveOwner`, `SwapOwner` |
| S2 | `disableModule` is immediate, and the post-check accepts exactly that removal | ADR 0016 | `test_SelfCall_DisableModuleImmediate`, `test_PostCheck_DisableModuleAcceptsExactRemoval`, `test_PostCheck_DisableModulePlusOtherListChangeReverts` |
| S2b | Timelocked self-calls use the 72h class | ADR 0016 | `test_Delays_SelfCallsUseEscapeClass72h` |
| S2c | The threshold-raise freeze is prevented | ADR 0016; threat model §3.5 | `test_SelfCall_ThresholdRaiseToNofNIsTimelocked`, `test_Guardian_CancelsQueuedThresholdRaise` |
| S3 | Post-check accepts only the authorized change | spec Post-check | `test_PostCheck_AuthorizedOwnerChangeAccepted`, `test_PostCheck_ChangeBeyondItemReverts` |
| S4 | Module parity: same pipeline, shared counters | threat model §3.3 | `test_ModulePath_SamePolicyOutcomeAsSigned` (table-driven over representative calls), `test_ModulePath_SharesOutflowBucket` |
| S5 | A module cannot clear the module guard | Step 3 quiz; ADR 0001 | `test_ModulePath_SetModuleGuardZeroRejected` |

## Phase 6: allowlist

| ID | Requirement | Source | Tests |
|---|---|---|---|
| A1 | Deny by default | P2; spec pipeline 5 | `test_Allowlist_UnlistedTargetReverts`, `test_Allowlist_UnlistedSelectorReverts`, `testFuzz_Allowlist_DenyByDefault` |
| A2 | Parameter constraints | spec pipeline 5; threat model §3.1 | `test_Allowlist_FixedRecipientEnforced`, `test_Allowlist_RecipientMismatchReverts` |
| A3 | Adding is timelocked; removing is immediate | P1; ADR 0002 | `test_Allowlist_AddIsTimelocked`, `test_Allowlist_RemoveIsImmediate` |
| A4 | Selector entries (target, selector, allowValue) for calldata of 4 bytes or more; `valueRecipient[target]` for empty calldata | ADR 0017 | `test_Allowlist_EthToValueRecipientPasses`, `test_Allowlist_EthToNonRecipientReverts`, `test_Allowlist_ValueWithoutAllowValueReverts`, `test_Allowlist_EmptyCalldataWithoutRecipientReverts`, `test_Outflow_ValueWithCalldataDebitsEthBucket` |
| A5 | Calldata of 1–3 bytes rejected | ADR 0017 | `testFuzz_Allowlist_CalldataOneToThreeBytesReverts` |
| A6 | Real `0x00000000` selector is an ordinary entry, and a value recipient doesn't allowlist it | ADR 0017 | `test_Allowlist_ZeroSelectorNeedsOwnEntry`, `test_Allowlist_ValueRecipientDoesNotAllowZeroSelector` |

## Phase 7: outflows

| ID | Requirement | Source | Tests |
|---|---|---|---|
| O1 | Unconfigured token has cap 0 | P2; ADR 0012 | `test_Outflow_UnconfiguredTokenTransferReverts` |
| O2 | ETH `value` counts | spec pipeline 7 | `test_Outflow_EthValueDebited`, `test_Outflow_EthOverCapReverts` |
| O3 | Approvals count in full; unlimited rejected; spender allowlisted | ADR 0004 | `test_Approval_CountsFullAmount`, `test_IncreaseAllowance_CountsIncrement`, `test_Approval_MaxUintReverts`, `test_Approval_UnlistedSpenderReverts` |
| O4 | Permit2 never allowlisted | ADR 0004 | `test_Approval_Permit2SpenderReverts`, `test_Config_AllowlistingPermit2Reverts` |
| O5 | Exact revocations always pass and are not counted | ADR 0004 | `test_Revocation_ApproveZeroPassesUnderHostileConfig`, `test_Revocation_NotDebited`, `test_Revocation_WithValueGoesThroughPipeline` |
| O6 | `setApprovalForAll(true)` hard reject; `(false)` passes | ADR 0004, 0009 | `test_SetApprovalForAll_TrueReverts`, `test_SetApprovalForAll_FalsePasses` |
| O7 | Token bucket mechanics | ADR 0012 | `test_Bucket_RefillsLinearly`, `test_Bucket_NeverExceedsCapacity`, `test_Bucket_DebitOnlyOnSuccess` (with `safeTxGas > 0` and a failing inner call) |
| O8 | Bounds: ≤ cap per transaction, ≤ 2× cap per 24h | spec Post-check; ADR 0012 | `testFuzz_Bucket_PerTxNeverExceedsCap`, `testFuzz_Bucket_Any24hWindowAtMost2xCap` |
| O9 | Cap changes | ADR 0012 | `test_Bucket_SettlesAtOldRateBeforeCapChange`, `test_Bucket_RaiseKeepsLevel`, `test_Bucket_RaiseIsTimelocked`, `test_Bucket_LowerClampsLevel`, `test_Bucket_LowerIsImmediate` |
| O10 | Batch accumulation | ADR 0003 item 6 | `test_Batch_OutflowAccumulatesAcrossInnerCalls` |
| O11 | Transient map: ≤ 8 tokens; the only assembly; no collisions | ADR 0005 | `test_TransientMap_EightTokensAccepted`, `test_TransientMap_NinthTokenRevertsTooManyTokens`, `test_TransientMap_EthCountsAsToken`, `test_TransientMap_NoCollisionWithTypedTransientVars`, `testFuzz_TransientMap_AddAndReadBack`, `test_TransientMap_ClearedAfterPostCheck` |
| O12 | Non-standard tokens | build plan Phase 7 | `test_WeirdToken_NoReturnValueTransferCounted`, `test_WeirdToken_FeeOnTransferCountsRequestedAmount`, `test_WeirdToken_RevertOnZeroApproveRevokedWithOne` |
| O12b | `approve(_, 0)` and `approve(_, 1)` skip the spender allowlist; 1 counts | ADR 0004 item 7 | `test_Approval_OneToUnlistedSpenderPassesAndCountsOne`, `test_Approval_TwoToUnlistedSpenderReverts`, `test_Approval_OneOnZeroDecimalTokenCountsAgainstCap`, `test_Approval_OneToPermit2Reverts`, `testFuzz_Approval_AnyNonZeroToPermit2Reverts`, `test_Revocation_ApproveZeroToPermit2Passes` |
| O13 | A transaction blocked by the cap becomes valid after refill (runbook) | ADR 0012; runbook | `test_Bucket_BlockedTxBecomesValidAfterRefill` (characterization) |

## Phase 8: proxy upgrades and singleton migration

| ID | Requirement | Source | Tests |
|---|---|---|---|
| P1 | Upgrade-class calls only as matured items | spec pipeline 6; ADR 0006 | `test_ProxyUpgrade_<Kind>_RevertsWithoutItem` and `_SucceedsWithMaturedItem`, for `UpgradeTo`, `UpgradeToAndCall`, `ProxyAdminUpgrade`, `ProxyAdminUpgradeAndCall`, `BeaconUpgradeTo`, `ChangeAdmin`, `TransferOwnership`, `GrantAdminRole`, `GrantUpgraderRole` |
| P2 | Binding re-checked at execute | ADR 0006 | `test_ProxyUpgrade_ImplAddressMismatchReverts`, `test_ProxyUpgrade_ImplCodehashChangedReverts` (metamorphic mock), `test_ProxyUpgrade_InitCalldataMismatchReverts` |
| P3 | Delay = max(7d, withdrawal period + 24h) | ADR 0011 | `testFuzz_ProxyUpgrade_DelayIsMaxOf7dAndWithdrawalPlus24h` |
| P4 | Withdrawal period rules | ADR 0011 | `test_WithdrawalPeriod_RaiseIs48h`, `test_WithdrawalPeriod_LowerWaitsCurrentUpgradeDelay`, `test_WithdrawalPeriod_RaiseCancelsPendingLowering` |
| P5 | Public event for queued upgrades | ADR 0006 | `test_Events_ProxyUpgradeQueued` |
| P6 | Singleton migration item, bound per item | ADR 0015 | `test_Migration_SucceedsAfter72hWithBoundSingleton`, `test_Migration_BeforeDelayReverts`, `test_Migration_UnboundMigrationContractReverts`, `test_Migration_MigrationContractCodehashChangedReverts`, `test_Migration_CalldataMismatchReverts`, `test_Migration_ResultingSingletonMismatchReverts`, `test_Migration_SingletonCodehashChangedReverts`, `test_Migration_RevertsIfGuardSlotsChanged`, `test_Migration_WithFallbackHandlerSelectorReverts`, `test_Migration_InsideBatchReverts` |

## Phase 9: install

| ID | Requirement | Source | Tests |
|---|---|---|---|
| I1 | Module-list hash checker | spec Install; deployment notes | `test_InstallChecker_PassesOnMatch`, `test_InstallChecker_RevertsOnMismatch`, `test_InstallChecker_RevertsWhenListLongerThanPage`, `test_InstallChecker_OrderSensitiveHash` |
| I2 | Revoke the scanned pairs, including Permit2 on every held token | ADR 0004 item 6 | `test_InstallBatch_RevokesScannedPairs`, `test_InstallBatch_RevokesPermit2OnEveryHeldToken` |
| I3 | Atomic batch | spec Install | `test_InstallBatch_CheckerFailureLeavesNothingInstalled`, `test_InstallBatch_RevokeFailureLeavesNothingInstalled` |
| I4 | Migration is a separate transaction | deployment notes; open item 9 (resolved) | `test_InstallBatch_DelegatecallInsideBatchReverts` |
| I5 | The install transaction gets no guard post-check | ADR 0001 | `test_Install_InstallTxNotPostChecked` (characterization) |
| I6 | Approval scan script | ADR 0004 items 6–7 | Script test on fixture logs: `scan_FindsAllApprovalPairs`, `scan_DeduplicatesPairs`, `scan_DryRunSwitchesToApproveOneOnZeroRevert`; fork: `test_Fork_BnbApproveZeroBehaviour` (fork only; open item 2) |

## Phase 10: stateful invariants

A handler mixes signed transactions, module transactions, batches, config changes and time warps.

| ID | Invariant | Source |
|---|---|---|
| V1 | `invariant_ProtectedSlotsChangeOnlyWithMaturedItem` | spec Post-check |
| V2 | `invariant_OutflowPerTokenWithinDocumentedBound` | ADR 0012 |
| V3 | `invariant_EscapeExecutableAfterDelay` | threat model R1 |
| V4 | `invariant_CancellationAlwaysPasses` | threat model R2 |
| V5 | `invariant_GuardianCannotBlockEscapeOrOwnRemoval` | ADR 0008 |
| V6 | `invariant_TransientStateClearBetweenExecutions` | ADR 0005 |
| V7 | `invariant_NoPermit2AllowanceEverGranted` | ADR 0004 |

## Phase 11: fork demo

| ID | Requirement | Tests |
|---|---|---|
| F1 | Bybit's Safe version and pre-hack state verified | `test_Fork_BybitSafeVersionAndState` (fork only; open item 1) |
| F2 | Migrate → install → replay the payload, which reverts | `test_Fork_BybitPayloadReverts` (fork only) |
| F3 | A legitimate proxy upgrade through the timelock succeeds | `test_Fork_LegitProxyUpgradeViaTimelock` (fork only) |

## Phase 12: alert bot (Rust)

| ID | Requirement | Tests |
|---|---|---|
| K1 | Decode every guard custom error from revert data | `decodes_every_guard_error` (generated from the ABI, so a new error without a decoder fails the test) |
| K2 | Failed-transaction source: re-run at the parent block | `replays_failed_tx_and_decodes` (fork dry run) |
| K3 | Alerts | `alerts_on_queued_with_countdown`, `alerts_on_guardian_action`, `alerts_on_expiry`, `alerts_on_cap_near_exhaustion` |
| K4 | Configuration and dry-run mode | `config_from_env`, `dry_run_against_fork` |

## Threat-model mitigations (§7) → tests

| Attack path | Tests |
|---|---|
| Batch inner calls skip the pre-check | D1–D7, O10 |
| Blocked transaction stays signed | B4 `test_Cancellation_ConsumesNonceAndKillsBlockedTx`, O13 |
| Deferred outflows via approvals | O3–O6, I2, V7 |
| Nested execution vs. caps | H2, H3, V6 |
| Gas refunds as an outflow | B3, H9 |
| Threshold raise freezes the Safe | S2c |
| Direct writes to guard slots via delegatecall | B7, B8, B10 |
| Anyone calls the hooks directly | H1 |

## ⚠️ Requirements with no on-chain test

| Item | Source | How it's covered instead |
|---|---|---|
| Monitoring: the bot runs and the guardian responds within the delay | threat model §6 | Trust assumption. Bot tests (K1–K4) cover detection only |
| Allowlist review for free parameters and hidden approvals | threat model §6; ADR 0004 | Process. Documented review checklist |
| Allowances on tokens that don't emit `Approval` | threat model §6 | Trust assumption. `scan_` tests show what the scan does find |
| Off-chain EIP-1271 signatures other than Permit2 | threat model §8 | Limitation. Characterization test `test_Limitation_Eip1271SignatureValidWithoutGuard` documents it |
| Cap-rate drain by a trusted module | threat model §8 | Limitation. Characterization test `test_Limitation_ModuleDrainsAtCapRate` |
| Allowlisted routes with free parameters | threat model §8 | Limitation. Covered by A2 for constrained routes |
| Behaviour of a future singleton, and arbitrary storage writes by the migration contract | ADR 0015 | Trust assumption: review of the bound code during the 72h delay |
| Factory and deployed bytecode are the reviewed versions | threat model §6 | Process. H8 checks canonical dependencies, not our own bytecode |

## Red-before-green rule

- Every Phase 2 test is run once against the **Phase 1 skeleton** (invariant I1.11, which allows by
  default) and **must fail** there. The run is recorded in the Phase 2 report. A Phase 2 test that
  passes on the skeleton isn't testing real policy.
- The same rule applies to each later phase, run against the previous phase's code.

## Tooling gates (not tests, checked every phase)

- `forge fmt --check`
- Slither, with findings in `docs/slither-triage.md`
- coverage on `src/`: 100% lines and at least 95% branches, with 100% for the transient map library
- `forge snapshot`
