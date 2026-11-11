#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
"""Require complete prefix transport, current sender and tenant storage proofs."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from ci_tag_consumer_proof import classify, report_regression_failed_on_assertion

PREFIX = "github.com/ctlplne/probectl/"
UNIT = {
    "internal/tags": (
        "TestNativeFlowFieldsCannotBeShadowedByTenantTags",
        "TestResolveRejectsMixedTenantContextAndUntrustedRuleShapes",
        "TestSnapshotPinsRevisionAndRejectsCrossContextSubject",
    ),
    "cmd/probectl-flow-agent": (
        "TestObservedFlowEvidenceKeepsCompleteRoutingWitnessChannel",
    ),
    "internal/pipeline": (
        "TestFlowCaptureConsumerKeepsOriginalDigestFrozenClockAndTenant",
        "TestFlowCaptureConsumerRefusesPartialUnscopedAndMismatchedResolution",
        "TestFlowProjectionUsesFrozenFirstProcessingClock",
        "TestSFlowStartTimeFallback",
    ),
    "cmd/probectl-bmp-listener": (
        "TestBMPEvidenceAdapterKeepsCompleteRoutingTransport",
    ),
    "internal/opendata": (
        "TestRPKICompleteValidatorSourceKeepsFullFamiliesASNsAndOriginalFreshness",
        "TestRPKICompleteValidatorSourceRefusesMalformedLateOrUnadmittedData",
        "TestRPKIValidatorSourceKeepsCompleteIntendedPopulationBeyondMonitoringPrefixes",
        "TestRPKISnapshotKeepsLargeMetadataAndOriginalSubsecondGeneration",
        "TestRPKISnapshotRefusesDisabledAmbiguousAndExpiredSourcesBeyondIPCache",
        "TestIXMembershipCacheKeepsCompletePortsExactSelectorsAndOriginalFreshness",
        "TestIXMembershipCacheRefusesPartialCorruptOrUnadmittedWholeManifests",
        "TestPeeringDBIXPrefixesKeepCompletePopulationClockAndOwnedMatches",
        "TestPeeringDBIXPrefixesRefusePartialAmbiguousOrMalformedSnapshot",
        "TestPeeringDBIXPrefixesKeepInactiveAndExpiredSourcesVisibleWithoutMemberships",
    ),
    "internal/config": (
        "TestRPKILocalConfigKeepsCompleteRaiseableAdmissionAndNoEgress",
        "TestPublicRoutingAdmissionIsFiniteRaiseableObservableAndOffline",
        "TestIXMembershipLocalConfigKeepsNoEgressAndIndependentPositiveFreshness",
        "TestFlowIXPrefixLocalConfigKeepsNoEgressAndPositiveFreshness",
    ),
    "internal/store/flowstore": (
        "TestPeeringTrafficKeepsCompleteOwnedPopulationStatesAndExactPartialIntervals",
        "TestPeeringTrafficRefusesMissingCurrentScopeBudgetAndInventedRows",
        "TestPeeringTrafficSQLBindsTenantOriginalClockAndWholeStatePopulation",
        "TestPeeringQueryDataBindsCompleteReferencesTargetDirectionAndImmutableStates",
        "TestPeeringQueryDataRefusesMixedUnprovenAndUnadmittedInputs",
        "TestPeeringQueryDigestIncludesOriginalStatesAndTargetPeer",
        "TestPeeringRoleScopeKeepsWholeCurrentOwnershipBeforeRouterSelection",
        "TestRoutingASNFiltersBindUnknownSeparatelyFromZeroAndKeepExclusions",
        "TestRoutingQueryProjectionKeepsWholeSharedPathsAndOriginalTenantKeys",
        "TestRoutingCaptureReferenceReadsKeepCompleteOriginalScopeAndAdmission",
        "TestFlowRoutingCaptureRowsPreserveRawIdentityAndTenant",
        "TestFlowRoutingCaptureRowsRefuseIncompleteOrForeignMetadata",
        "TestFlowRoutingCaptureCHWireRetainsCompleteReferencesAndExpiry",
        "TestInterfaceRoleQueryProjectionKeepsTenantIdentityAndCompleteMetadata",
        "TestInterfaceRoleQueryProjectionRefusesAmbiguousExpiredOrPartialInputs",
        "TestInterfaceRoleExplorerPreservesBothDirectionsMissingRowsAndTenantBoundary",
        "TestInterfaceRoleExplorerSQLKeepsFixedTenantJoinAndCompleteExternalValues",
    ),
    "internal/flow": (
        "TestPeeringPartialIntervalRanksExactCombinedRatesWithoutTruncatingWindow",
        "TestPeeringPartialIntervalRefusesMissingForeignCanceledAndUnadmittedInputs",
        "TestPeeringPercentileServiceSeamKeepsExactCombinedRateAndObservedZeros",
        "TestPeeringPercentileServiceSeamRefusesForeignMissingAndPartialInputs",
        "TestRoutingRegistryKeepsCompletePathsUnknownASNsAndEveryQueryAxis",
        "TestRoutingQuerySelectorsRequireTheBGPSourcePlaneOnEveryAxis",
        "TestOriginalFlowDigestPreservesUntrustedAndCloudPayloadWithoutAuthority",
        "TestFlowEvidencePreservesEveryConfiguredDomainBeyondTransportAndCachePages",
        "TestFlowRoutingWorkerKeepsCompleteEligibleRecordsWithoutWaitingOnRPC",
        "TestFlowRoutingWitnessProducerRefusesForeignUnconfiguredAndPartialMetadata",
        "TestWhollyUnresolvedFlowEvidenceRetriesAfterOneMinute",
        "TestFlowEvidenceRequiresExactConfiguredExporter",
        "TestFlowEvidenceClaimsAreBoundedAndDoNotUseUnlistedExporter",
        "TestRoutingCaptureWitnessBindsEveryOriginalFieldAndUnknownWireData",
        "TestRoutingCaptureWitnessPreservesCompleteValuesAndRefusesPartialAdmission",
        "TestPeeringEstimateCombinesIntervalsBeforeExactPercentile",
        "TestPeeringEstimateRefusesForeignMissingPartialAndUnadmittedInputs",
        "TestInterfaceRoleQuerySelectorsRequireAllSourcePlanesAndCompleteInputs",
    ),
    "internal/device": (
        "TestSNMPPollInterfaceAddressesKeepDualStackWholeEpochAndTenantEvidence",
        "TestSNMPInterfaceAddressesRefusePartialMalformedOrUnadmittedTables",
        "TestSNMPPollPrefixEvidenceKeepsCompleteEpochAndUnavailableFence",
        "TestSNMPPollPrefixEvidenceRetainsWholePopulationAndOwnsInput",
        "TestSNMPPollSkipsExtraPrefixFetchWithoutEvidenceChannel",
    ),
    "internal/ai/mcp": (
        "TestPeeringNativeToolKeepsExactInputsTenantAndEverySourcePermission",
        "TestPeeringNativeFinalEncodingRetainsFairnessAndExactCountersWithTextRedaction",
        "TestNativeRoutingASNsKeepStructuredPathsAndMandatoryTextRedaction",
        "TestBGPRoutingNativeToolsKeepCompleteInputAndTenantUserBoundary",
        "TestBGPRoutingNativeParserRefusesAuthorityHintsAndIncompleteReplacement",
        "TestInterfaceRoleNativeToolsPreserveCompleteInputAndUserTenantBoundary",
        "TestInterfaceRoleNativeExplanationRequiresEverySourceBeforeBackend",
    ),
    "internal/cli": (
        "TestPeeringCLIAndGeneratedSDKKeepExactTenantBoundInputsAndQualifiedOutput",
        "TestInterfaceRoleCLIUsesOwnedRoutesAndExactDecimalRevision",
        "TestInterfaceRoleCompletePolicyReachesNamedRawCLIAndGeneratedSDK",
    ),
    "internal/control": (
        "TestPeeringNativeProjectionKeepsWholePublicContractAndExactMetadata",
        "TestPeeringAPIKeepsExactPublicIdentitiesAndQualifiedCompleteOutput",
        "TestPeeringNativeUnprovenSelectorsRetainMandatoryPIIRedaction",
        "TestPeeringHTTPRefusesTenantAndAuthorityHintsBeforeServiceReads",
        "TestPeeringSummaryCombinesTransitBeforeP95AndKeepsUnknownVolumes",
        "TestPeeringSummaryKeepsMissingIntervalsUnprovenAndRefusesLateCorruption",
        "TestPeeringServiceRequiresCurrentTenantUserBeforeCaptureSelection",
        "TestPeeringTargetKeepsWholeOwnedLANMembershipAndOriginalGenerations",
        "TestPeeringTargetRefusesForeignScopeBeforePublicAvailabilityAndAdmission",
        "TestPeeringTargetRequiresExactCurrentLANBindingRoleAndMembership",
        "TestBuildRPKIEnrichmentKeepsLocalCompleteSourceAndUnavailableHealth",
        "TestNativeRoutingCSVPagesKeepCompleteTypedPathsAndExactSourceRecords",
        "TestNativeFlowRoutingPathsKeepWholeTypedSegmentsAcrossQueryProjections",
        "TestReportRoutingReaderRequiresCurrentScopedAuthorityBeyondReceipt",
        "TestReportRoutingRequirementsKeepWholeOriginalPeriodsAndAdmission",
        "TestReportRoutingRequirementsRefuseOmittedAndMalformedSourceLineage",
        "TestReportRoutingContextRequirementsKeepTheBGPSourceGrant",
        "TestReportCanonicalSourcesRequireCompleteContextLineageAndCurrentPermissions",
        "TestFlowRoutingValidityKeepsCompleteOriginalSelectorsAndAdmission",
        "TestRoutingSnapshotRefusesMissingForeignAndExtraneousAuthority",
        "TestFlowRoutingSnapshotRequiresCurrentTenantUserBeforeReferenceReads",
        "TestBGPRoutingMCPMetadataKeepsStoredIDsAndFullUntrustedRedaction",
        "TestNativeFlowRoleProjectionHonorsCancellationAndExistingTenantScope",
        "TestNativeFlowRoleProjectionRetainsCompleteTenantProvenance",
        "TestNativeFlowRoleProjectionRefusesForeignMissingStaleOrChangedIdentity",
        "TestInterfaceRoleMCPMetadataKeepsExactGeneratedIDsAndFullTextRedaction",
        "TestInterfaceRoleMCPMetadataRefusesMalformedIdentifiersAndRevisions",
        "TestInterfaceRoleIXSourceMatchesOnlyOwnedCurrentInputsAndPreservesOverrides",
        "TestBuildEnrichmentIXPrefixFailureRemainsVisibleAndMakesNoOutboundSource",
        "TestBuildMembershipInputKeepsUnavailableVisibleWithoutOutboundSources",
        "TestFlowRoleSnapshotRequiresCurrentTenantUserBeforeStorage",
        "TestRoleSnapshotReceiptRefusesMissingOrForeignAuthority",
        "TestReportRoleContextCapturePreservesTagsAndCurrentSourceRequirements",
        "TestInterfaceRoleConfigurationRoutesRequireSeparateReadAndWriteGrants",
        "TestInterfaceRoleExplanationJoinsCompleteOwnedFactsAndPreservesOverride",
        "TestInterfaceRoleExplanationRefusesForeignCanceledAndIncompleteAdmission",
        "TestInterfaceRolePeerAssociationSharesMultiPeerAdmission",
        "TestInterfaceRolePublicationRejectsChangedOrWithdrawnContributors",
        "TestInterfaceRoleOwnedManualOverrideDoesNotInventSourceFreshness",
        "TestInterfaceRoleConfiguredEvaluationKeepsCompleteOrderAndVersionedSources",
        "TestInterfaceRoleConfiguredEvaluationRefusesForeignInvalidAndPartialResults",
        "TestInterfaceRoleConfiguredEvaluationAdmitsExpansionBeforeCompilation",
        "TestInterfaceRoleConfiguredEvaluationKeepsOverrideAcrossWithdrawalAndReset",
        "TestOpenAPIMatchesRoutes",
        "TestOpenAPISecurityModelMatchesRoutes",
        "TestOpenAPISecurityGateCatchesPlantedDefects",
        "TestAuditPolicyMatrixCoversRequiredRoutes",
    ),
    "internal/store/flowsnapshot": (
        "TestSnapshotsKeepWholeSourceValidityUnderConfiguredAdmission",
    ),
    "internal/entity": (
        "TestPublicRoutingAssignmentCannotAuthorizeEntityObservations",
        "TestFlowCaptureKeyBindsTenantCertifiedSenderTupleAndEveryDigestByte",
        "TestFlowCaptureKeyRefusesMissingSenderMalformedScopeAndUnscopedAddresses",
        "TestSNMPPrefixSnapshotKeepsCompleteOwnedCanonicalRows",
        "TestSNMPPrefixSnapshotRejectsPartialMalformedAndForeignClaims",
        "TestSNMPPrefixSnapshotAdmissionNeverTruncatesToFit",
        "TestInterfaceRolePolicyCompleteReachKeepsOrderAndOwnedCopies",
        "TestInterfaceRolePolicyRefusesAmbiguityAndKeepsCanonicalSets",
    ),
    "internal/agent": (
        "TestPublicMRTImporterStreamsWholeInputAndKeepsExactAmbiguousRetries",
        "TestPublicMRTImporterRefusesPartialReplacedUnadmittedAndCanceledSources",
        "TestPublicMRTFileCompressionRequiresCleanWholeEOF",
        "TestPublicMRTImporterReportsFailedRetirementAndRefusesEmptyFirstRecord",
        "TestPublicRoutingClientKeepsOriginalFramesAndRequiresExclusiveReceipts",
        "TestFlowRoutingClientRequiresCompleteOrderedCertifiedReceipts",
        "TestRoutingResetClientRequiresExactInvalidationReceipt",
        "TestRoutingMessageClientKeepsExactStreamAndRefusesMixedReceipts",
        "TestRoutingStageClientPreservesCompleteRequestAndRequiresPrivateReceipt",
        "TestSNMPPrefixEvidenceWireKeepsCompleteSetAndWholeRequestAdmission",
    ),
    "internal/agenttransport": (
        "TestRoutingCapturePolicyKeepsConfiguredAdmissionAcrossOptionOrder",
        "TestEntityEvidenceEnvelopeKeepsOnePlaneAndRefusesUnknownPublicFields",
        "TestFlowRoutingWitnessReceiverKeepsCompleteBatchAndCertifiedScope",
        "TestFlowRoutingWitnessReceiverRefusesMixedMalformedAndUnknownAuthority",
        "TestRoutingProjectionKeepsWholePopulationAndAdmitsDescriptorExpansion",
        "TestSNMPPrefixReceiverKeepsPresenceAndRefusesPartialTables",
    ),
    "internal/bgp": (
        "TestPeeringPathsKeepFullASNOrderedMembershipAndAllPathConsensus",
        "TestPeeringPathsRefuseMalformedLateUnadmittedAndCanceledEvidence",
        "TestMRTRIBKeepsWholeDualFamilyPathsAttributesClocksAndExplicitAddPath",
        "TestMRTRIBRefusesWholeLateMalformedForeignPeerAndUnadmittedRecords",
        "TestMRTPeerIndexKeepsWholeWirePopulationBinaryIdentityAndEmptySource",
        "TestMRTPeerIndexRefusesWholeLateMalformedUnadmittedAndCanceledRecords",
        "TestAnalyzerBridgeKeepsCompleteOldAndNewPathsAndTenantBinding",
        "TestAnalyzerBridgeRefusesUnadmittedWholeLineWithoutPublishingPrefix",
        "TestRoutingPathTextKeepsCompleteCanonicalSegmentsAndAdmission",
        "TestRoutingPathFieldsKeepCompleteSemanticsAndExplicitUnknowns",
        "TestRoutingPathFieldsRefuseWholeAdmissionMalformedAndCancelledInput",
        "TestFRRRoutingProfileKeepsOriginalMetadataFamiliesAndStrictDefault",
        "TestFRRRoutingProfileRefusesUnknownAmbiguousAndUnadmittedSources",
        "TestBMPRoutingSourceLossRetiresAllSelectorsAfterSocketDeregistration",
        "TestBMPRoutingSelectorsKeepIndependentGenerationsRefusalsAndSourceClosure",
        "TestBMPRoutingCohortsKeepOneSocketFamiliesSequencesAndWholeReplacement",
        "TestRoutingCohortReceiptRequiresCompleteUniqueGeneration",
        "TestBMPRoutingMetadataAdmissionKeepsWholePopulationAndReclaimsSourceState",
        "TestBMPRoutingEvidenceFailureKeepsRawSessionAndRetiresOnlyOwnedGenerations",
        "TestBMPRoutingQueueLossKeepsRawSessionAndInvalidatesBeforePendingData",
        "TestBMPRoutingLossWakesIdleEvidenceWorkerWithoutClosingRawSource",
        "TestRoutingLifecycleRequiresCompleteMatchingSourceFrame",
        "TestBMPRoutingWholeStreamKeepsFIFOAndResetsOnSourceClosure",
        "TestBMPRoutingStagingUsesAdmittedIdentityAndCompleteOriginalPeerUp",
        "TestBMPRoutingMappedPeerRetainsWholeOpaqueSelectorThroughRealTLS",
        "TestRoutingPeerUpKeepsCompleteDeclaredFamiliesAndRefusesMalformedSource",
        "TestLocRIBPeerUpKeepsExplicitFamilyCohortsAndAdjacentDefaults",
        "TestRoutingMessageDispatchKeepsCompleteFamiliesAndNoInventedCompletion",
        "TestBMPSourceChangesKeepCompleteDualFamilyPathsWithdrawalsAndAttributes",
        "TestBMPSourceChangesRefuseMissingMandatoryFieldsAndLateMalformedTail",
        "TestBMPSourceChangesKeepExclusiveCompletionAndWholeAdmission",
        "TestBMPPeerUpPreservesMalformedRealSourceCapabilityDiagnosis",
        "TestBMPSourceRouteBindsPeerButUsesActualViewEncodingAndWireClock",
        "TestBMPSourceRouteRefusesOtherPeerMalformedEnvelopeAndPartialAdmission",
        "TestBMPEvidenceReconnectRestatesCurrentPeersWithoutPerRouteWrites",
        "TestBMPUpdateFrameUsesReceivingCapabilityAndKeepsFullProtocolMaximum",
        "TestBMPUpdateFrameRefusesMissingMalformedSourceAndWholeOperationAdmission",
    ),
    "internal/store": (
        "TestPeeringCaptureMatchKeepsOriginalStructuredPathsAndTenantBeforeAdmission",
        "TestPeeringCaptureMatchKeepsPublicProvenanceAndExplicitAbsence",
        "TestRoutingRPKICaptureKeepsWholeEvidenceOriginalClockAndTenantBoundary",
        "TestRoutingRPKICaptureRefusesForgedStalePartialAndUnadmittedEvidence",
        "TestRoutingRPKICapturePreservesUnknownPublicOriginsAndCompleteNotFound",
        "TestPublicCaptureQueryProjectionKeepsExactPathsSourceCohortAndExplicitProvenance",
        "TestPublicCaptureKeepsWholeOriginalCohortAndSeparatesObservationClocks",
        "TestPublicCaptureKeepsCompletePrefixAbsenceAndRefusesPartialForeignOrForgedFacts",
        "TestPublicCaptureRejectsClockCohortOmissionsAndVersionDowngrades",
        "TestPublicMRTRoutingProjectionKeepsOriginalSourceFactsAndRefusesInvalidMetadata",
        "TestPublicMRTManifestKeepsOriginalEmptySourceAndPeerWireIdentity",
        "TestPublicMRTManifestRefusesForgedPeerClockUnsupportedSourceAndPartialAdmission",
        "TestPublicSnapshotLookupRequiresTenantAndWholeAdmissionBeforeStorage",
        "TestPublicSnapshotMessageKeepsWholePathsExactReplayAndExclusiveCompletion",
        "TestPublicSnapshotMessageRefusesLatePartialShapeBudgetAndForeignScope",
        "TestPublicSnapshotFreshnessUsesOriginalClockAndIndependentAuthorityLimits",
        "TestPublicSnapshotManifestKeepsBothFamiliesWholeIdentityExactClocksAndEmptyPresence",
        "TestPublicSnapshotManifestRefusesLatePartialBudgetAndForeignTenantBeforeStorage",
        "TestPublicRoutingAuthorityRequiresTenantBeforeStorageAndCompleteAssignment",
        "TestPublicRoutingMetadataKeepsWholeSourceIdentityWithoutInventedBMP",
        "TestPublicRoutingMetadataRefusesMixedViewsAndCannotGrantRouterWrites",
        "TestRetainedRoutingQueryFieldsKeepWholePathsAndExplicitAmbiguity",
        "TestRoutingCaptureServiceRequiresTenantBeforeAvailability",
        "TestRoutingCaptureRepositoryRequiresTenantBeforeStorage",
        "TestRoutingCaptureObjectsKeepEveryFieldAndShareContentAcrossClocks",
        "TestRoutingCaptureObjectsKeepExplicitSelectionsAndUnavailableDirections",
        "TestRoutingCaptureObjectsRefuseTenantMixCorruptionOldFormatsAndPartialAdmission",
        "TestRoutingCaptureObjectsRejectRehashedSemanticAndTenantCorruption",
        "TestRoutingCaptureObjectsPreserveCompleteLargePathAndAttributes",
        "FuzzRoutingCaptureObjects",
        "TestRoutingStreamProtocolSelectorOnlyRefusesCanonicalSelection",
        "TestRoutingBindingManifestKeepsExactSelectorsAndRefusesAmbiguity",
        "TestRoutingStoredSerializerRequiresCurrentBindingAndCompleteFamilies",
        "TestRoutingBindingReaderRefusesUnknownCorruptAndForeignMetadata",
        "TestRoutingSelectionReaderRefusesUnknownBorrowedAndIncompleteBindings",
        "TestInterfaceRoleCASUsesExactIdentityAndDecimalRevision",
        "TestBGPRoutingAuthorityRequiresTenantAndCompleteSourceBeforeStorage",
        "TestBGPRoutingLookupRequiresTenantExactViewAndWholeAdmissionBeforeStorage",
        "TestRoutingFlowCaptureCannotChooseOwnerFromPayloadOrPartialEvidence",
        "TestRoutingFlowProjectionKeepsEveryPathAndRejectsPartialAdmission",
        "TestRoutingNextHopASRequiresActualUniqueNeighborAndCompleteProvenance",
        "TestRoutingNextHopASRefusesLateMalformedUnadmittedAndForeignScope",
        "TestBGPRoutingRouterLookupRequiresExactTenantContextBeforeStorage",
        "TestBGPRoutingViewMetadataKeepsStablePeerSlotsAndCompleteValues",
        "TestBGPRoutingViewMetadataRefusesIncompleteShapeAndWholeAdmission",
        "TestBGPRoutingBeginRefusesForeignTenantBeforeMetadataOrStorage",
        "TestBGPRoutingBatchKeepsCompleteValuesAndReplayIdentity",
        "TestBGPRoutingBatchRefusesWholeMalformedOrUnadmittedInput",
        "TestBGPRoutingHeartbeatRequiresExclusiveFrameAndPositiveServerLease",
        "TestInterfaceRoleStorageRequiresTenantBeforeAnyQuery",
        "TestInterfaceRoleInputsRequireTenantBeforeStorageAndCanonicalPeerValues",
        "TestInterfaceRoleFlowBindingRequiresTenantBeforeStorageAndExactIdentity",
    ),
    "ee/silo": (
        "TestRoutingCapturePlanKeepsTenantReferencesAndImmutableRole",
        "TestBGPRoutingPlanKeepsEveryReferenceInItsTenantSchema",
        "TestBGPRoutingBindingPlanPreservesStoredCollectorContextOnCatchUp",
        "TestEntityRegistryForeignKeysFollowAllSiloCopies",
        "TestInterfaceRoleStoragePlanKeepsLocalKindAndTenantForeignKeys",
    ),
}
FLOW_INTEGRATION = {
    "internal/store/flowstore": (
        "TestPeeringTrafficRealStoreKeepsWholeTenantStatesDirectionsAndOriginalClock",
        "TestInterfaceRoleExplorerClickHouseKeepsTenantDirectionsAndCompleteTotals",
    ),
}
INTEGRATION = {
    "internal/store/flowsnapshot": (
        "TestSnapshotsPostgresWholeSourceValidityKeepsChargeTenantAndCurrentRead",
    ),
    "internal/bgp": ("TestBMPLocRIBRealRouterKeepsCompletePeerAndFamilyMarkers",),
    "cmd/probectl-control": ("TestMCPFlowSourcesRetainConfiguredLocalIXGeneration",),
    "ee/silo": (
        "TestBGPRoutingBindingStorageKeepsManagedHybridAndOldSchemaBoundaries",
        "TestInterfaceRoleAPIKeepsSiloRelationsLockedBeforeConfigurationSQL",
        "TestInterfaceRoleInputsFollowManagedAndHybridCurrentAuthority",
    ),
    "internal/control": (
        "TestEntityAdminAssignmentIsTenantAndContextBound",
        "TestRoutingContextRequiresCurrentBGPPolicyAndPreservesSibling",
        "TestRoutingFieldsPreserveUnknownTrafficAcrossServedAndNativeReaders",
        "TestReportRoutingCurrentReaderKeepsOriginalReceiptAndSingleConnectionAuthority",
        "TestReportRoutingSourceStorageKeepsWholePeriodsAndTenantAdmission",
        "TestReportRoleSourcesKeepCurrentCanonicalContextsWithoutTags",
        "TestBGPRoutingBindingsStdioKeepsTenantEpochAndCurrentCredentials",
        "TestBGPRoutingConfigurationAPIKeepsTenantCurrentActorEpochAndAtomicAudit",
        "TestNativeFlowRoleTLSKeepsWholeProvenanceAndCurrentAuthority",
        "TestInterfaceRoleNativeTLSKeepsTenantConfigurationAndCurrentSources",
        "TestInterfaceRoleStdioKeepsWholePoliciesAndRechecksCredentialWithinStream",
        "TestFlowRoleQueryKeepsCurrentOwnedSourcesAndRefusesPublicationChanges",
        "TestInterfaceRoleFrozenObjectsKeepWholePagesCSVAndCurrentAuthority",
        "TestInterfaceRoleConfigurationAPIKeepsCompletePoliciesTenantCASAndAtomicAudit",
        "TestInterfaceRoleExplanationServesOwnedSourcesAndCurrentAuthority",
        "TestPeeringTargetStoreKeepsCurrentTenantGrantAndPublicationAuthority",
        "TestPeeringEstimateAPIKeepsCurrentTenantSourcesAndUnprovenEmptyIntervals",
        "TestInterfaceRoleExplanationRefusesMidComputationAuthorityChanges",
        "TestInterfaceRoleExplanationEvaluatesCompleteSavedPolicyWithDefaultAdmission",
    ),
    "internal/store": (
        "TestPublicRoutingAuthorityKeepsTenantPurposeCurrentCredentialAndAssignmentBirth",
        "TestPublicFlowFallbackKeepsOriginalCaptureAndCurrentTenantSourceAuthority",
        "TestPublicContextLookupKeepsWholeAssignedCohortTenantAndPrefixAbsence",
        "TestPublicMRTRecordsKeepOriginalPathsTenantScopeAndWholeSourceRefusal",
        "TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions",
        "TestPublicSnapshotStagingKeepsWholeTenantManifestReplayRollbackAndEmptyWithdrawal",
        "TestPublicRoutingSnapshotSchemaKeepsEmptyRIBTenantSourceAndBoundViewIdentity",
        "TestPublicRoutingStagingKeepsTenantPrivateOwnedMetadataAndAtomicReplacement",
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges",
        "TestPeeringCaptureReaderKeepsCurrentTargetTenantAndOriginalSourceAuthority",
        "TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone",
        "TestRoutingOperatorConfigurationKeepsTenantPolicyCASAndAtomicAudit",
        "TestRoutingBindingManifestKeepsTenantEpochTargetsAndWholeAdmission",
        "TestRoutingBindingManifestRefusesLegacyAuthorityWithoutChangingOtherTenant",
        "TestBGPRoutingBoundAuthorityKeepsBaseCredentialsEpochBirthAndTenant",
        "TestRoutingBoundSerializerLookupRefusesChangedRetainedFormat",
        "TestBGPRoutingStagingKeepsTenantRetryLeaseAndAtomicCompletePeer",
        "TestRoutingStageReplacementWithdrawsOmittedFamiliesWithoutAffectingSibling",
        "TestRoutingStageKeepsDisjointCohortsAndRetiresWholeOverlap",
        "TestRoutingBoundStagingKeepsSelectorIncarnationsAndSourceWideRefusal",
        "TestBGPRoutingWholeStreamKeepsFamilyAtomicityReplayAndTenantFence",
        "TestRoutingBoundStreamKeepsWholeCurrentGenerationsAndRefusalIsolation",
        "TestRoutingBoundSerializerKeepsCurrentFormatAndCompleteFamilyCohort",
        "TestInterfaceRoleInputsKeepCurrentOwnedSourcesAndNegativeFences",
        "TestInterfaceRoleInputsRetainWholePrefixTableAndRefusePartialBudget",
        "TestInterfaceRoleInputsRequireAuthenticatedFaultClockAndRecovery",
        "TestInterfaceRoleInputsRequireExplicitBMPOriginRouterBinding",
        "TestInterfaceRoleFlowBindingsKeepCurrentExplicitOriginsAndTenantScope",
        "TestEntityRegistryTenantAndContextIsolation",
        "TestSNMPPrefixStorageKeepsCompleteWirePopulationAndRepairsManagedCopies",
        "TestDashboardReportTenantIsolation",
        "TestInterfaceRoleConfigurationPostgresKeepsTenantCASAndOverrideIncarnations",
        "TestBGPRoutingSchemaKeepsTenantFamilyPathIdentityAndPublicationShape",
        "TestBGPRoutingLookupKeepsLongestPrefixEveryPathTenantFamilyAndSelectedView",
        "TestRoutingFlowCaptureRequiresUniqueCurrentExporterAndKeepsTenantRoutes",
        "TestBGPRoutingRouterLookupUsesOwnContextAndRefusesConflictingCompleteViews",
        "TestBGPRoutingLookupRefusesChangedAuthorityClockCorruptionAndMixedSnapshots",
        "TestBGPRoutingAuthorityKeepsCurrentTenantOriginPurposeAndAssignmentEpoch",
        "TestBGPRoutingBeginKeepsPrivateTenantGenerationsAndAtomicSlotReplacement",
        "TestBGPRoutingWritesSerializeSourceChangesAndRejectStaleSnapshots",
        "TestBGPRoutingQuotaWaitUsesFreshTenantAccountAndRefusesOldSnapshots",
        "TestBGPRoutingBatchesKeepCompleteTenantPathsReplayWithdrawalAndPublication",
        "TestBGPRoutingBatchRefusalInvalidatesWithoutPartialWritesOrEpochRevival",
        "TestBGPRoutingBatchRollsBackLateStorageFaultAndOriginExpiry",
        "TestBGPRoutingResetClosesKnownGenerationBeforeRefusedReplacement",
        "TestBGPRoutingHeartbeatKeepsIncarnationSequenceClockAndTenantLease",
        "TestBGPRoutingMessageClockRejectsLegacyWritersAndUnusableHeartbeats",
    ),
    "internal/agenttransport": (
        "TestPublicMRTNativeCommandPublishesWholeFileAndRejectsCorruptCompression",
        "TestPublicRoutingOriginalMRTRealMTLSKeepsTenantCurrentSourceAndWholeRefusal",
        "TestPublicRoutingRealMTLSKnownSourceRefusalCommitsWithoutSiblingDamage",
        "TestFlowRoutingWitnessRealMTLSKeepsTenantFirstReceiptAndCurrentSender",
        "TestRoutingStagingRealMTLSKeepsTenantOriginRetryAndPrivateState",
        "TestRoutingPeerUpRateRefusalInvalidatesOnlyItsCurrentOwnedSource",
        "TestRoutingMalformedUnboundPeerUpPreservesKnownContexts",
        "TestRoutingFRRProfileRequiresCurrentOperatorBindingThroughRealMTLS",
        "TestRoutingMappedVRFRequiresCurrentBindingThroughRealMTLS",
        "TestSNMPPrefixRealMTLSKeepsTenantSenderReplayAndCompleteMetadata",
    ),
    "internal/tenantlife": (
        "TestRoutingCaptureSubjectDecodedErasureKeepsFirstReceiptAndSibling",
        "TestInterfaceRoleSubjectKeepsWholeExportErasureAndTenantIsolation",
        "TestEntityEvidenceSubjectMetadataExportErasureAndIsolation",
    ),
}
ROOT = "TestSNMPPrefixEvidenceWireKeepsCompleteSetAndWholeRequestAdmission"
MARKER = "combined complete prefix request escaped whole-wire admission"



def overlay_source_path(out, filename):
    """Go discovery ignores these files; explicit overlays still read their bytes."""
    assert Path(filename).name == filename and filename.endswith(".go")
    return out / ("_" + filename)


def artifact_selftest():
    """Exercise real Go discovery and an assertion-failing overlay in a tiny module."""
    with tempfile.TemporaryDirectory(prefix="probectl-prefix-artifact-") as directory:
        root = Path(directory).resolve()
        (root / "go.mod").write_text("module artifactproof\n\ngo 1.26\n")
        out = root / "artifacts/interface-prefix-transport"
        out.mkdir(parents=True)
        for package in ("alpha", "beta"):
            source = root / package / "value.go"
            source.parent.mkdir()
            source.write_text(f"package {package}\nconst Value = 1\n")
            overlay_source_path(out, package + ".go").write_text(
                f"package {package}\nconst Value = 2\n"
            )
        test = root / "alpha/value_test.go"
        test.write_text('package alpha\nimport "testing"\nfunc TestArtifactOverlay(t *testing.T) { if Value != 1 { t.Fatal("artifact overlay executed the mutation") } }\n')
        listed = subprocess.run(["go", "list", "./..."], cwd=root,
                                text=True, capture_output=True, check=True, timeout=60)
        assert set(listed.stdout.splitlines()) == {"artifactproof/alpha", "artifactproof/beta"}, listed
        positive = subprocess.run(["go", "test", "-count=1", "-json", "./alpha"], cwd=root,
                                  text=True, capture_output=True, timeout=60, check=False)
        assert not classify(positive.stdout, positive.returncode,
                            package="artifactproof/alpha", tests=("TestArtifactOverlay",)), positive
        overlay = out / "alpha.json"
        overlay.write_text(json.dumps({"Replace": {
            str(root / "alpha/value.go"): str(overlay_source_path(out, "alpha.go"))
        }}))
        negative = subprocess.run(["go", "test", "-count=1", "-json", "-overlay", str(overlay), "./alpha"],
                                  cwd=root, text=True, capture_output=True, timeout=60, check=False)
        assert report_regression_failed_on_assertion(
            negative.stdout, negative.returncode, package="artifactproof/alpha",
            root="TestArtifactOverlay", child="", marker="artifact overlay executed the mutation"
        ), negative
    print("Go discovery ignores mutation artifacts and explicit overlays retain exact assertions")


def selftest():
    def encode(values):
        return "\n".join(json.dumps(row) for row in values)

    for package, roots in list(UNIT.items()) + list(INTEGRATION.items()) + list(FLOW_INTEGRATION.items()):
        events = [
            {"Package": PREFIX + package, "Test": root, "Action": action}
            for root in roots
            for action in ("run", "pass")
        ] + [{"Package": PREFIX + package, "Action": "pass"}]
        options = {"package": PREFIX + package, "tests": roots}
        assert not classify(encode(events), 0, **options)
        for root in roots:
            assert classify(
                encode([row for row in events if row.get("Test") != root]), 0, **options
            )
            assert classify(
                encode(
                    events
                    + [{"Package": PREFIX + package, "Test": root, "Action": "skip"}]
                ),
                0,
                **options,
            )
        assert classify("", 0, **options)
        assert classify(encode(events), 1, **options)
    assert ROOT in UNIT["internal/agent"]
    control = [
        {"Package": PREFIX + "internal/agent", "Test": ROOT, "Action": "run"},
        {
            "Package": PREFIX + "internal/agent",
            "Test": ROOT,
            "Action": "output",
            "Output": MARKER,
        },
        {"Package": PREFIX + "internal/agent", "Test": ROOT, "Action": "fail"},
        {"Package": PREFIX + "internal/agent", "Action": "fail"},
    ]
    options = {
        "package": PREFIX + "internal/agent",
        "root": ROOT,
        "marker": MARKER,
        "child": "",
    }
    assert report_regression_failed_on_assertion(encode(control), 1, **options)
    assert not report_regression_failed_on_assertion(encode(control), 0, **options)
    assert not report_regression_failed_on_assertion(
        encode(control[:1] + control[2:]), 1, **options
    )
    assert not report_regression_failed_on_assertion("compiler error", 1, **options)
    unrelated = [dict(row, Test="TestRoutingStageClientPreservesCompleteRequestAndRequiresPrivateReceipt") if "Test" in row else row for row in control]
    assert not report_regression_failed_on_assertion(encode(unrelated), 1, **options)
    print("Prefix transport classifier refuses missing, skipped and unrelated proof")


def execute(package, roots, label, integration=False, overlay=None, child=""):
    # The complete positive package batch exceeded five minutes before its
    # last native protocol root finished. Keep every root and give that
    # combined workload its own allowance; exact omission runs stay bounded.
    go_timeout = "15m" if overlay is None else "5m"
    process_timeout = 960 if overlay is None else 360
    args = ["go", "test", "-race", "-count=1", "-timeout=" + go_timeout, "-json"]
    if integration:
        args += ["-tags=integration"]
    if overlay is not None:
        args += ["-overlay", str(overlay)]
    pattern = "^(" + "|".join(roots) + ")$"
    if child:
        assert len(roots) == 1
        pattern += "/^" + child + "$"
    result = subprocess.run(
        args + ["-run", pattern, "./" + package],
        text=True,
        capture_output=True,
        timeout=process_timeout,
        check=False,
    )
    out = Path("artifacts/interface-prefix-transport")
    out.mkdir(parents=True, exist_ok=True)
    (out / (label + ".jsonl")).write_text(result.stdout)
    (out / (label + ".stderr.txt")).write_text(result.stderr)
    print(result.stdout, end="")
    print(result.stderr, end="")
    return result



def bgp_source_peer_control():
    source = Path("internal/bgp/route_source_message.go").resolve()
    original = source.read_text()
    seam = "if !sameBMPRoutePeer(route, peer.Header) {"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    mutant = overlay_source_path(out, "bmp_route_peer_omitted.go")
    mutant.write_text(original.replace(seam, "if false && !sameBMPRoutePeer(route, peer.Header) {"))
    overlay = out / "bmp_route_peer_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestBMPSourceRouteRefusesOtherPeerMalformedEnvelopeAndPartialAdmission"
    result = execute("internal/bgp", (root,), "bmp_route_peer_omitted", overlay=overlay)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/bgp", root=root,
        child="", marker="route from another peer or malformed envelope exposed source metadata"
    ):
        raise RuntimeError("BMP route peer control did not fail its exact assertion")


def bgp_source_origin_control():
    source = Path("internal/bgp/route_source_changes.go").resolve()
    original = source.read_text()
    seam = "if !sourceHasOrigin(frame.Update.Attributes) {"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    mutant = overlay_source_path(out, "bmp_route_origin_omitted.go")
    mutant.write_text(original.replace(seam, "if false && !sourceHasOrigin(frame.Update.Attributes) {"))
    overlay = out / "bmp_route_origin_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestBMPSourceChangesRefuseMissingMandatoryFieldsAndLateMalformedTail"
    result = execute("internal/bgp", (root,), "bmp_route_origin_omitted", overlay=overlay, child="origin")
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/bgp", root=root,
        child="origin", marker="invalid source changes exposed partial routing data"
    ):
        raise RuntimeError("BMP route origin control did not fail its exact assertion")


def bgp_peer_session_control():
    source = Path("internal/bgp/bmp_entity_evidence.go").resolve()
    original = source.read_text()
    seam = "sessionHandle: peer.sessionHandle, routerAgentID: peer.routerAgentID"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    mutant = overlay_source_path(out, "bmp_evidence_session_omitted.go")
    mutant.write_text(original.replace(seam, "sessionHandle: 0, routerAgentID: peer.routerAgentID"))
    overlay = out / "bmp_evidence_session_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestBMPEvidenceReconnectRestatesCurrentPeersWithoutPerRouteWrites"
    result = execute("internal/bgp", (root,), "bmp_evidence_session_omitted", overlay=overlay)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/bgp", root=root,
        child="", marker="fresh authenticated BMP session reused old peer evidence suppression"
    ):
        raise RuntimeError("BMP evidence session control did not fail its exact assertion")


def bgp_routing_extended_control():
    source = Path("internal/bgp/route_extended.go").resolve()
    original = source.read_text()
    seam = "if receiver.extended {"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    mutant = overlay_source_path(out, "routing_extended_receiver_omitted.go")
    mutant.write_text(original.replace(seam, "if receiver.extended || sent.extended || received.extended {"))
    overlay = out / "routing_extended_receiver_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestBMPUpdateFrameUsesReceivingCapabilityAndKeepsFullProtocolMaximum"
    result = execute("internal/bgp", (root,), "routing_extended_receiver_omitted", overlay=overlay)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/bgp", root=root,
        child="", marker="extended UPDATE guessed receiver permission from sender capability"
    ):
        raise RuntimeError("extended UPDATE receiver control did not fail its exact assertion")


def bgp_routing_authority_control():
    source = Path("internal/store/bgp_routing_authority.go").resolve()
    original = source.read_text()
    seam = " AND origin.spiffe_id='spiffe://probectl/tenant/' || source.tenant_id::text || '/bmp/' || source.source_ref"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    mutant = overlay_source_path(out, "routing_origin_purpose_omitted.go")
    mutant.write_text(original.replace(seam, " AND true"))
    overlay = out / "routing_origin_purpose_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestBGPRoutingAuthorityKeepsCurrentTenantOriginPurposeAndAssignmentEpoch"
    result = execute("internal/store", (root,), "routing_origin_purpose_omitted",
                     integration=True, overlay=overlay, child="origin-purpose")
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/store", root=root,
        child="origin-purpose", marker="changed source/credential retained routing authority"
    ):
        raise RuntimeError("routing origin purpose control did not fail its exact assertion")


def snmp_dual_stack_address_control():
    source = Path("internal/device/snmp.go").resolve()
    original = source.read_text()
    seam = "collectSNMPModernAddresses(ctx, conn, &inv)"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    mutant = overlay_source_path(out, "snmp_modern_addresses_omitted.go")
    mutant.write_text(original.replace(seam, "_ = ctx"))
    overlay = out / "snmp_modern_addresses_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestSNMPPollInterfaceAddressesKeepDualStackWholeEpochAndTenantEvidence"
    result = execute("internal/device", (root,), "snmp_modern_addresses_omitted", overlay=overlay)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/device", root=root,
        child="", marker="complete dual-stack IP-MIB addresses were lost",
    ):
        raise RuntimeError("dual-stack address omission did not fail its exact assertion")



def bgp_routing_generation_control():
    source = Path("internal/store/bgp_routing_views.go").resolve()
    original = source.read_text()
    seam = " WHERE tenant_id=$1 AND context_id=$2 AND router_id=$3 AND collector_agent_id=$4"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    mutant = overlay_source_path(out, "routing_slot_retirement_omitted.go")
    mutant.write_text(original.replace(seam, seam.replace(" WHERE ", " WHERE false AND ")))
    overlay = out / "routing_slot_retirement_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestBGPRoutingBeginKeepsPrivateTenantGenerationsAndAtomicSlotReplacement"
    result = execute("internal/store", (root,), "routing_slot_retirement_omitted", integration=True, overlay=overlay)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/store", root=root,
        child="", marker="peer restart mixed former, sibling or unrelated route generations"
    ):
        raise RuntimeError("routing slot retirement control did not fail its exact assertion")


ROUTING_WRITE_CONTROLS = {
    "peering-target-current-grants": (
        "internal/control/peering_target_store.go",
        "if !allowed {",
        "if false && !allowed {",
        "TestPeeringTargetStoreKeepsCurrentTenantGrantAndPublicationAuthority", "",
        "actual peering target bypassed current source-plane permission",
    ),
    "peering-target-publication": (
        "internal/control/peering_target_store.go",
        "if !previous.Eligible || !current.Eligible || current.InputDigest != previous.InputDigest || current.Target != previous.Target || current.RouterID != previous.RouterID || current.PrefixVersion != previous.PrefixVersion || current.MemberVersion != previous.MemberVersion {",
        "if false && (!previous.Eligible || !current.Eligible || current.InputDigest != previous.InputDigest || current.Target != previous.Target || current.RouterID != previous.RouterID || current.PrefixVersion != previous.PrefixVersion || current.MemberVersion != previous.MemberVersion) {",
        "TestPeeringTargetStoreKeepsCurrentTenantGrantAndPublicationAuthority", "",
        "peering target publication reused a changed complete public generation",
    ),
    "peering-target-scope": (
        "internal/control/peering_target.go",
        "if !bound || err != nil || scope != target.Scope || tenant.String() != scope.TenantID || in.Scope != scope || in.InterfaceID != target.InterfaceID {",
        "if false && (!bound || err != nil || scope != target.Scope || tenant.String() != scope.TenantID || in.Scope != scope || in.InterfaceID != target.InterfaceID) {",
        "TestPeeringTargetRefusesForeignScopeBeforePublicAvailabilityAndAdmission", "",
        "peering target consulted public availability before the tenant boundary",
    ),
    "peering-role-router": (
        "internal/store/flowstore/peering_roles.go",
        "if row.Scope == scope && row.RouterID == routerID {\n\t\t\trows = append(rows, row)",
        "if true {\n\t\t\trows = append(rows, row)",
        "TestPeeringRoleScopeKeepsWholeCurrentOwnershipBeforeRouterSelection", "",
        "peering role selection lost complete interfaces or renewed the original clock",
    ),
    "peering-role-current": (
        "internal/store/flowstore/peering_roles.go",
        "if err := d.validate(ctx, scope.TenantID, now); err != nil {",
        "if err := d.validate(ctx, scope.TenantID, now); false && err != nil {",
        "TestPeeringRoleScopeKeepsWholeCurrentOwnershipBeforeRouterSelection", "",
        "peering selection pruned expired full-source authority",
    ),
    "peering-path-unordered": (
        "internal/bgp/peering_path.go",
        "unordered = true",
        "ordered = true",
        "TestPeeringPathsKeepFullASNOrderedMembershipAndAllPathConsensus", "set",
        "peering path eligibility flattened unordered/confederation data or ignored another original path",
    ),
    "peering-path-consensus": (
        "internal/bgp/peering_path.go",
        "consensus = PeeringPathAmbiguous",
        "consensus = state",
        "TestPeeringPathsKeepFullASNOrderedMembershipAndAllPathConsensus", "mixed-paths",
        "peering path eligibility flattened unordered/confederation data or ignored another original path",
    ),
    "peering-path-complete": (
        "internal/bgp/peering_path.go",
        "for _, path := range paths {\n\t\tfor _, segment := range path {\n\t\t\tif err := ctx.Err();",
        "for _, path := range paths[:min(1, len(paths))] {\n\t\tfor _, segment := range path {\n\t\t\tif err := ctx.Err();",
        "TestPeeringPathsRefuseMalformedLateUnadmittedAndCanceledEvidence", "",
        "matching first path hid malformed late peering evidence",
    ),
    "peering-capture-context": (
        "internal/store/bgp_routing_capture_query_batch.go",
        "if err := authorize(ctx, record); err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t\tpreauthorized = record.ContextID",
        "if err := authorize(ctx, record); false && err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t\tpreauthorized = record.ContextID",
        "TestPeeringCaptureReaderKeepsCurrentTargetTenantAndOriginalSourceAuthority", "",
        "empty peering selection or tiny budget bypassed current context authority",
    ),
    "peering-capture-router": (
        "internal/store/bgp_routing_capture_query_batch.go",
        "AND facts.searchable_body#>>'{data,Owner,RouterID}'=$4",
        "AND $4::text<>''",
        "TestPeeringCaptureReaderKeepsCurrentTargetTenantAndOriginalSourceAuthority", "",
        "peering reader selected captures from another canonical router",
    ),
    "peering-query-state-digest": (
        "internal/store/flowstore/peering_query_data.go",
        "refs = append(refs, reference{row.Key, row.Clock, states})",
        "refs = append(refs, reference{row.Key, row.Clock, peeringQueryStates{}})",
        "TestPeeringQueryDigestIncludesOriginalStatesAndTargetPeer", "",
        "peering digest omitted an original state or target peer",
    ),
    "peering-traffic-owner": (
        "internal/store/flowstore/peering_traffic.go",
        "!owners[owner{address.Unmap().String(), row.Protocol, row.ObsDomain}]",
        "false",
        "TestPeeringTrafficKeepsCompleteOwnedPopulationStatesAndExactPartialIntervals", "",
        "peering aggregation dropped owned unknown/state traffic, included another router/tenant, truncated counters or lost partial intervals",
    ),
    "peering-partial-duration": (
        "internal/flow/peering_partial.go",
        "duration := min(window.Interval, window.To.Sub(values[i].start))",
        "duration := window.Interval",
        "TestPeeringPartialIntervalRanksExactCombinedRatesWithoutTruncatingWindow", "",
        "partial interval lost exact full-window combined rate",
    ),
    "peering-summary-combine": (
        "internal/control/peering_summary.go",
        "eligible = append(eligible, fact)",
        "_ = fact",
        "TestPeeringSummaryCombinesTransitBeforeP95AndKeepsUnknownVolumes", "",
        "peering service summed per-link percentiles or lost original hand calculation",
    ),
    "peering-summary-coverage": (
        "internal/control/peering_summary.go",
        "if !result.CompleteObservedInputs {",
        "if false && !result.CompleteObservedInputs {",
        "TestPeeringSummaryKeepsMissingIntervalsUnprovenAndRefusesLateCorruption", "",
        "peering service manufactured observed zeros for a missing interval",
    ),
    "peering-native-permissions": (
        "internal/ai/mcp/peering.go",
        'ExtraPermissions: []string{"ai.query", "entities.read", "metrics.read", "events.read"}',
        'ExtraPermissions: []string{"ai.query", "entities.read", "metrics.read"}',
        "TestPeeringNativeToolKeepsExactInputsTenantAndEverySourcePermission", "",
        "native peering bypassed a source-plane grant",
    ),
    "peering-native-unproven-selector": (
        "internal/control/mcp_peering.go",
        "if value.Target.Eligible {",
        "if true {",
        "TestPeeringNativeUnprovenSelectorsRetainMandatoryPIIRedaction", "",
        "unproven peering selector bypassed mandatory PAN redaction",
    ),
    "peering-native-admission": (
        "internal/ai/mcp/peering.go",
        "Admit: admit",
        "Admit: nil",
        "TestPeeringNativeFinalEncodingRetainsFairnessAndExactCountersWithTextRedaction", "",
        "peering admission released before final encoding",
    ),
    "peering-traffic-states": (
        "internal/store/flowstore/peering_traffic.go",
        "state: query.Data.stateForRow(row)",
        'state: "unavailable"',
        "TestPeeringTrafficKeepsCompleteOwnedPopulationStatesAndExactPartialIntervals", "",
        "peering aggregation dropped owned unknown/state traffic, included another router/tenant, truncated counters or lost partial intervals",
    ),
    "peering-query-key-clock": (
        "internal/store/flowstore/peering_query_data.go",
        "data.states[routingQueryKey{key, row.RoutingCapturedUnixNanos}]",
        "data.states[routingQueryKey{key, data.routing.asOf.UnixNano()}]",
        "TestPeeringQueryDataBindsCompleteReferencesTargetDirectionAndImmutableStates", "",
        "peering lookup replaced an original capture clock",
    ),
    "peering-query-target-scope": (
        "internal/store/flowstore/peering_query_data.go",
        "row.Scope != target.Scope || row.Peering == nil",
        "false || row.Peering == nil",
        "TestPeeringQueryDataRefusesMixedUnprovenAndUnadmittedInputs", "",
        "peering query accepted a mixed target or unproven late state",
    ),
    "peering-target-lan": (
        "internal/control/peering_target.go",
        "if match.LANID != target.LANID {",
        "if false && match.LANID != target.LANID {",
        "TestPeeringTargetRequiresExactCurrentLANBindingRoleAndMembership", "wrong-lan",
        "peering target admitted unavailable or mismatched IX/owner evidence",
    ),
    "peering-target-freshness": (
        "internal/control/peering_target.go",
        "members.ValidUntil.After(at)",
        "(true || members.ValidUntil.After(at))",
        "TestPeeringTargetRequiresExactCurrentLANBindingRoleAndMembership", "expired-members",
        "peering target admitted unavailable or mismatched IX/owner evidence",
    ),
    "rpki-capture-whole": (
        "internal/store/bgp_rpki_capture.go",
        "Covering: covering,",
        "Covering: covering[:0],",
        "TestRoutingRPKICaptureKeepsWholeEvidenceOriginalClockAndTenantBoundary", "",
        "RPKI capture lost whole original validator evidence",
    ),
    "rpki-capture-clock": (
        "internal/store/bgp_rpki_capture.go",
        "capture.ObservedAt.After(at) || !capture.ValidUntil.After(at) ||",
        "",
        "TestRoutingRPKICaptureRefusesForgedStalePartialAndUnadmittedEvidence", "",
        "RPKI capture accepted forged or stale independent evidence",
    ),
    "rpki-capture-wire": (
        "internal/store/bgp_rpki_capture.go",
        "if service.rpki == nil {",
        "if true || service.rpki == nil {",
        "TestPublicFlowFallbackKeepsOriginalCaptureAndCurrentTenantSourceAuthority", "",
        "authenticated public flow omitted original complete validator evidence",
    ),
    "rpki-source-current": (
        "internal/opendata/rpki_source.go",
        "s.Current = s.Enabled && s.complete && !s.ObservedAt.IsZero() && !s.ObservedAt.After(at) && s.ValidUntil.After(at)",
        "s.Current = s.Enabled && s.complete",
        "TestRPKICompleteValidatorSourceKeepsFullFamiliesASNsAndOriginalFreshness", "",
        "copying stale validator bytes renewed their generation",
    ),
    "rpki-source-eof": (
        "internal/opendata/rpki_json.go",
        "if _, err := decoder.Token(); !errors.Is(err, io.EOF) {",
        "if _, err := decoder.Token(); false && !errors.Is(err, io.EOF) {",
        "TestRPKICompleteValidatorSourceRefusesMalformedLateOrUnadmittedData", "",
        "partial or malformed validator export became authoritative",
    ),
    "public-flow-current-source": (
        "internal/store/bgp_routing_capture_finalization.go",
        "if side.Public != nil {",
        "if false && side.Public != nil {",
        "TestPublicFlowFallbackKeepsOriginalCaptureAndCurrentTenantSourceAuthority", "",
        "public retained reader bypassed current original source authority",
    ),
    "public-capture-projection": (
        "internal/store/bgp_public_capture_query.go",
        'out.Fields[prefix+"bgp_provenance"] = provenance',
        'out.Fields[prefix+"bgp_provenance"] = "router_selected"',
        "TestPublicCaptureQueryProjectionKeepsExactPathsSourceCohortAndExplicitProvenance", "",
        "public native projection changed paths or invented router/RPKI authority",
    ),
    "public-capture-clocks": (
        "internal/store/bgp_public_capture.go",
        "public.Sources = append([]BGPPublicRoutingLookup(nil), public.Sources...)",
        "public.Sources = public.Sources",
        "TestPublicCaptureKeepsWholeOriginalCohortAndSeparatesObservationClocks", "",
        "public capture clock splitting mutated original source observations",
    ),
    "public-capture-admission": (
        "internal/store/bgp_routing_capture_admission.go",
        "chargePublicRoutingCapture(ctx, side.Public, budget)",
        "error(nil)",
        "TestPublicCaptureKeepsCompletePrefixAbsenceAndRefusesPartialForeignOrForgedFacts", "",
        "public capture bypassed complete binary source admission",
    ),
    "public-capture-authority": (
        "internal/store/bgp_routing_capture_finalization.go",
        "if _, err := (BGPRouting{}).publicSourceAuthorityInScope(ctx, sc, original.Source, lock); err != nil {",
        "if err := error(nil); err != nil {",
        "TestPublicContextLookupKeepsWholeAssignedCohortTenantAndPrefixAbsence", "",
        "retained public capture kept expired original source authority",
    ),
    "public-context-complete": (
        "internal/store/bgp_public_context.go",
        "part := remaining",
        "refs = refs[:1]; part := remaining",
        "TestPublicContextLookupKeepsWholeAssignedCohortTenantAndPrefixAbsence", "",
        "public context omitted a source or changed complete longest-prefix evidence",
    ),
    "public-context-prefix": (
        "internal/store/bgp_public_context.go",
        "got.Prefix.Bits() > out.Prefix.Bits()",
        "false",
        "TestPublicContextLookupKeepsWholeAssignedCohortTenantAndPrefixAbsence", "",
        "public context omitted a source or changed complete longest-prefix evidence",
    ),
    "public-read-absence": (
        "internal/store/bgp_public_lookup.go",
        "// A proved absence needs its original complete source for capture-time",
        "if lookupErr != nil { return BGPPublicRoutingLookup{}, lookupErr }; // A proved absence needs its original complete source for capture-time",
        "TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions", "",
        "complete public no-prefix result discarded its original source authority",
    ),
    "public-mrt-import-reset": (
        "internal/agent/public_mrt_stream.go",
        "err = errors.Join(err, reset())",
        "err = errors.Join(err)",
        "TestPublicMRTImporterRefusesPartialReplacedUnadmittedAndCanceledSources", "partial-header",
        "public MRT importer published partial or refused source without reset",
    ),
    "public-mrt-import-eof": (
        "internal/agent/public_mrt_stream.go",
        "complete := errors.Is(readErr, io.EOF) && len(raw) == 0",
        "complete := len(raw) == 0",
        "TestPublicMRTFileCompressionRequiresCleanWholeEOF", "gzip-truncated",
        "compressed public MRT corruption became a complete EOF",
    ),
    "public-mrt-envelope": (
        "internal/agenttransport/entity_evidence.go",
        "if !validEntityEvidenceEnvelope(req) {",
        "if false && !validEntityEvidenceEnvelope(req) {",
        "TestPublicRoutingOriginalMRTRealMTLSKeepsTenantCurrentSourceAndWholeRefusal", "mixed-envelope",
        "served public MRT accepted a mixed evidence envelope",
    ),
    "public-mrt-stage-refusal": (
        "internal/store/bgp_public_mrt_stage.go",
        "if err := invalidatePublicSource(ctx, sc, source); err != nil {",
        "if err := error(nil); err != nil {",
        "TestPublicRoutingRealMTLSKnownSourceRefusalCommitsWithoutSiblingDamage", "malformed-stage",
        "served public MRT refusal retained former current paths",
    ),
    "public-receipt-stage": (
        "internal/agent/bgp_routing_stage.go",
        "hasPublicRoutingReceipt(response)",
        "false",
        "TestRoutingStageClientPreservesCompleteRequestAndRequiresPrivateReceipt", "",
        "routing staging accepted missing, partial or published receipt",
    ),
    "public-mrt-refusal": (
        "internal/store/bgp_public_mrt_message.go",
        "errors.Is(err, bgp.ErrMRTRecord)",
        "false",
        "TestPublicMRTRecordsKeepOriginalPathsTenantScopeAndWholeSourceRefusal", "malformed-known-source",
        "malformed MRT source was not atomically invalidated",
    ),
    "public-mrt-reset": (
        "internal/store/bgp_public_message_store.go",
        "profile, !input.Reset)",
        "profile, true)",
        "TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions", "mrt-empty-source-record",
        "MRT source reset required route-data admission",
    ),
    "public-mrt-record": (
        "internal/store/bgp_public_snapshot_plan.go",
        "sourceRecordDigest = crypto.Hash(input.SourceRecord)",
        "sourceRecordDigest = nil",
        "TestPublicMRTManifestKeepsOriginalEmptySourceAndPeerWireIdentity", "",
        "MRT manifest lost original ASN encoding",
    ),
    "mrt-rib-whole": (
        "internal/bgp/mrt_rib.go",
        "validateSourceRouteAttributes(entry.Attributes)",
        "func() error { return nil }()",
        "TestMRTRIBRefusesWholeLateMalformedForeignPeerAndUnadmittedRecords", "",
        "MRT RIB exposed an earlier path from a refused whole record",
    ),
    "mrt-peer-framing": (
        "internal/bgp/mrt_peer_index.go",
        "if len(raw) != 0 {",
        "if false && len(raw) != 0 {",
        "TestMRTPeerIndexRefusesWholeLateMalformedUnadmittedAndCanceledRecords", "",
        "MRT source exposed partial peers after whole-record refusal",
    ),
    "public-read-source": (
        "internal/store/bgp_public_lookup.go",
        "store.publicSourceAuthorityInScope(ctx, sc, source, false)",
        "BGPRoutingSourceAuthority{AsOf: time.Now(), ValidUntil: time.Now().Add(time.Hour)}, error(nil)",
        "TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions", "read-revoked",
        "public reader accepted a revoked collector",
    ),
    "public-read-manifest": (
        "internal/store/bgp_public_manifest_reader.go",
        "if !bytes.Equal(digest[:], header.manifestDigest) {",
        "if false && !bytes.Equal(digest[:], header.manifestDigest) {",
        "TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions", "read-manifest",
        "public reader accepted changed complete source metadata",
    ),
    "public-message-sequence": (
        "internal/store/bgp_public_message_store.go",
        'if input.Sequence != header.nextSequence || header.state != "staging" {',
        'if header.state != "staging" {',
        "TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions", "gap",
        "public completion manufactured data or lost a genuine empty source",
    ),
    "public-message-atomic": (
        "internal/store/bgp_public_message_store.go",
        '"ROLLBACK TO SAVEPOINT public_snapshot_message"',
        '"SELECT 1"',
        "TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions", "",
        "rejected public message committed partial route writes",
    ),
    "public-message-manifest": (
        "internal/store/bgp_public_message_store.go",
        "verifyPublicSnapshotManifest(ctx, sc, birth, input.SnapshotID, header, profile)",
        "func() error { return nil }()",
        "TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions", "corrupt-manifest",
        "public completion manufactured data or lost a genuine empty source",
    ),
    "public-source-freshness": (
        "internal/store/bgp_public_source_clock.go",
        "origin := time.Unix(0, *sourceClock)",
        "origin := asOf",
        "TestPublicSnapshotFreshnessUsesOriginalClockAndIndependentAuthorityLimits", "",
        "public source lease came from receipt time or lost original nanoseconds",
    ),
    "routing-tag-shadow": (
        "internal/tags/resolver.go",
        '"src_bgp_provenance": true',
        '"native_reserved_fixture": true',
        "TestNativeFlowFieldsCannotBeShadowedByTenantTags", "src_bgp_provenance",
        'native query field "src_bgp_provenance" admitted as a tenant tag key',
    ),
    "public-snapshot-manifest": (
        "internal/store/bgp_public_snapshot_plan.go",
        "for _, definition := range input.Definitions {",
        "for _, definition := range input.Definitions[:min(1,len(input.Definitions))] {",
        "TestPublicSnapshotManifestKeepsBothFamiliesWholeIdentityExactClocksAndEmptyPresence", "",
        "whole public peer manifest lost identity, family or finite admission",
    ),
    "public-snapshot-retry": (
        "internal/store/bgp_public_snapshot_replay.go",
        'if !identical || state == "invalid" || !until.After(asOf) {',
        'if identical || state == "invalid" || !until.After(asOf) {',
        "TestPublicSnapshotStagingKeepsWholeTenantManifestReplayRollbackAndEmptyWithdrawal", "",
        "exact public retry changed its private generation",
    ),
    "public-snapshot-rls": (
        "internal/store/bgp_public_snapshot_schema_integration_test.go",
        "f.pool.Exec(ctx, string(definition))",
        'f.pool.Exec(ctx, string(definition)+"; ALTER TABLE bgp_public_snapshots DISABLE ROW LEVEL SECURITY")',
        "TestPublicRoutingSnapshotSchemaKeepsEmptyRIBTenantSourceAndBoundViewIdentity", "",
        "empty public snapshot leaked tenants, lost exact time or escaped tenant admission",
    ),
    "public-source-managed": (
        "ee/silo/bgp_routing_plan.go",
        'plan = append(plan, publicSourceChecksPlan(q+"."+quoteIdent("entity_source_contexts")))',
        '// public source schema catch-up omitted',
        "TestBGPRoutingBindingStorageKeepsManagedHybridAndOldSchemaBoundaries", "siloed",
        "managed public source assignment was refused after schema catch-up",
    ),
    "public-stage-slot": (
        "internal/store/bgp_public_views.go",
        "AND source_kind='public_bgp' AND peer_key=$5 AND afi=$6 AND safi=$7 AND state IN ('staging','current')",
        "AND source_kind='public_bgp' AND $5::bytea IS NOT NULL AND afi=$6 AND safi=$7 AND state IN ('staging','current')",
        "TestPublicRoutingStagingKeepsTenantPrivateOwnedMetadataAndAtomicReplacement", "",
        "public staging replacement mixed slots or tenant generations",
    ),
    "public-source-purpose": (
        "internal/store/bgp_public_authority.go",
        "AND sender.spiffe_id='spiffe://probectl/tenant/' || source.tenant_id::text || '/entity/' || source.agent_id",
        "-- source credential purpose omitted",
        "TestPublicRoutingAuthorityKeepsTenantPurposeCurrentCredentialAndAssignmentBirth", "purpose",
        "revoked or replaced public source retained current routing authority",
    ),
    "public-source-birth": (
        "internal/store/bgp_public_authority.go",
        "AND source.assigned_at<=$6 AND assignment.assigned_at<=$6 AND sender.issued_at<=$6",
        "AND assignment.assigned_at<=$6 AND sender.issued_at<=$6",
        "TestPublicRoutingAuthorityKeepsTenantPurposeCurrentCredentialAndAssignmentBirth", "rebound",
        "revoked or replaced public source retained current routing authority",
    ),
    "public-peer-presence": (
        "internal/store/bgp_public_metadata.go",
        "identity := peer",
        "identity := peer; identity.PeerBGPIdentifier = nil",
        "TestPublicRoutingMetadataKeepsWholeSourceIdentityWithoutInventedBMP", "",
        "absent public peer identifier aliased an explicitly observed zero",
    ),
    "ix-membership-current": (
        "internal/opendata/peeringdb_memberships.go",
        "out.Current = out.Enabled && p.availability(at) == nil",
        "out.Current = out.Enabled",
        "TestIXMembershipCacheKeepsCompletePortsExactSelectorsAndOriginalFreshness", "",
        "expired membership remained eligible",
    ),
    "ix-membership-complete": (
        "internal/opendata/peeringdb_memberships.go",
        "for _, row := range manifest.Data {",
        "for _, row := range manifest.Data[:min(1,len(manifest.Data))] {",
        "TestIXMembershipCacheKeepsCompletePortsExactSelectorsAndOriginalFreshness", "",
        "complete IX membership lost ports or included inactive records",
    ),
    "routing-registry": (
        "internal/flow/query_fields.go",
        "\tregisterRoutingQueryFields()",
        "\t// Routing registration omitted.",
        "TestRoutingRegistryKeepsCompletePathsUnknownASNsAndEveryQueryAxis", "",
        "complete routing field is absent from the shared query registry",
    ),
    "routing-complete-filter": (
        "internal/flow/query_predicates.go",
        "MaxQueryValueBytes = MaxPlanGrammarBytes",
        "MaxQueryValueBytes = 64 * 1024",
        "TestRoutingRegistryKeepsCompletePathsUnknownASNsAndEveryQueryAxis", "",
        "routing plan lost complete path, matrix, percentile, rows or historical reach",
    ),
    "routing-null-predicate": (
        "internal/store/flowstore/explorer_clickhouse.go",
        'result = "ifNull(" + result + ",0)"',
        '_ = result',
        "TestRoutingASNFiltersBindUnknownSeparatelyFromZeroAndKeepExclusions", "",
        "routing SQL lost bound values or two-valued nested exclusion",
    ),
    "report-routing-bgp-global": (
        "internal/control/explorer_flow_routing.go",
        'for _, permission := range []string{ai.PermEntitiesRead, "events.read"}',
        'for _, permission := range []string{ai.PermEntitiesRead}',
        "TestReportRoutingCurrentReaderKeepsOriginalReceiptAndSingleConnectionAuthority", "",
        "routing report reader accepted a credential without BGP event access",
    ),
    "report-routing-bgp-context": (
        "internal/control/explorer_flow_routing_authority.go",
        'for _, permission := range []string{permAIQuery, permFlowRead, "entities.read", "events.read"}',
        'for _, permission := range []string{permAIQuery, permFlowRead, "entities.read"}',
        "TestRoutingContextRequiresCurrentBGPPolicyAndPreservesSibling", "",
        "routing context reader reused BGP evidence after its context denial",
    ),
    "report-routing-bgp-requirements": (
        "internal/control/dashboard_report_contexts.go",
        'allowed, []string{permFlowRead, "entities.read", "events.read"}',
        'allowed, []string{permFlowRead, "entities.read"}',
        "TestReportRoutingContextRequirementsKeepTheBGPSourceGrant", "",
        "report routing context omitted its BGP source-plane grant",
    ),
    "routing-query-bgp-permissions": (
        "internal/flow/query_plan.go",
        'if ok && field.Derived == "flow_routing" && !slices.Contains(result, "events.read") {',
        'if false && ok && field.Derived == "flow_routing" && !slices.Contains(result, "events.read") {',
        "TestRoutingQuerySelectorsRequireTheBGPSourcePlaneOnEveryAxis", "",
        "routing selector omitted its BGP source-plane grant",
    ),
    "analyzer-bridge-complete-paths": (
        "internal/bgp/bridge.go",
        "const maxEventLine = 16 << 20",
        "const maxEventLine = 1 << 20",
        "TestAnalyzerBridgeKeepsCompleteOldAndNewPathsAndTenantBinding", "",
        "complete bound analyzer paths were refused or lost tenant admission",
    ),
    "native-routing-csv-paths": (
        "internal/control/mcp_native_flow_csv.go",
        "projectNativeCSVRoutingPaths(ctx, &out, remaining)",
        "func() error { _ = remaining; return nil }()",
        "TestNativeRoutingCSVPagesKeepCompleteTypedPathsAndExactSourceRecords", "",
        "native routing CSV lost complete typed paths or absolute cell positions",
    ),
    "routing-path-text": (
        "internal/bgp/routing_path_text.go",
        "segment.Values = append(segment.Values, uint32(value))",
        "if len(segment.Values) == 0 { segment.Values = append(segment.Values, uint32(value)) }",
        "TestRoutingPathTextKeepsCompleteCanonicalSegmentsAndAdmission", "",
        "complete routing path text lost canonical values",
    ),
    "native-routing-paths": (
        "internal/control/mcp_native_flow_routing.go",
        "value.RoutingPaths = complete",
        "_ = complete",
        "TestNativeFlowRoutingPathsKeepWholeTypedSegmentsAcrossQueryProjections", "",
        "native routing projection lost complete typed paths",
    ),
    "report-routing-current-reader": (
        "internal/control/dashboard_report_routing.go",
        "if current.digest != input.Routing.Digest || current.inputDigest != input.Routing.InputDigest {",
        "if false && (current.digest != input.Routing.Digest || current.inputDigest != input.Routing.InputDigest) {",
        "TestReportRoutingCurrentReaderKeepsOriginalReceiptAndSingleConnectionAuthority", "",
        "report reader reused changed original routing source proof",
    ),
    "report-routing-source-read": (
        "internal/store/report_artifact_body.go",
        "CASE WHEN octet_length(a.source_capture::text)<=$4 THEN a.source_capture ELSE NULL END",
        "CASE WHEN octet_length(a.source_capture::text)<=1048576 AND octet_length(a.source_capture::text)<=$4 THEN a.source_capture ELSE NULL END",
        "TestReportRoutingSourceStorageKeepsWholePeriodsAndTenantAdmission", "",
        "actual report source read lost complete original periods",
    ),
    "report-routing-source-admission": (
        "internal/store/report_artifact_body.go",
        "ReportArtifactSourceEnvelopeMaxBytes = 64 << 20",
        "ReportArtifactSourceEnvelopeMaxBytes = 1 << 20",
        "TestReportRoutingRequirementsKeepWholeOriginalPeriodsAndAdmission", "",
        "report refused complete original routing selectors above former source envelope",
    ),
    "report-routing-publication-lock": (
        "internal/store/bgp_routing_capture_report.go",
        "if !held {",
        "if false && !held {",
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges", "",
        "report routing reader accepted an unheld publication audit lock",
    ),
    "report-role-scheduler-ceiling": (
        "internal/control/dashboard_report_source_scheduler.go",
        '"metrics.read", "events.read", permAIQuery',
        '"metrics.read", permAIQuery',
        "TestReportRoleSourcesKeepCurrentCanonicalContextsWithoutTags", "",
        "role-only report could not capture its admitted sources",
    ),
    "report-role-context-capture": (
        "internal/control/dashboard_report_sources.go",
        "ctx = context.WithValue(ctx, reportContextCaptureKey{}, scope)",
        "_ = scope",
        "TestReportRoleSourcesKeepCurrentCanonicalContextsWithoutTags", "",
        "role-only report lost complete canonical source context",
    ),
    "report-role-context-read": (
        "internal/control/dashboard_report_source_access.go",
        "for _, requirement := range capture.Contexts {",
        "for _, requirement := range capture.Contexts[:0] {",
        "TestReportRoleSourcesKeepCurrentCanonicalContextsWithoutTags", "",
        "report reader reused role source after its context denial",
    ),
    "flow-routing-validity-size": (
        "internal/store/flowsnapshot/stage.go",
        "int64(len(input.Validity)) > s.config.privateHeaderBytes()",
        "len(input.Validity) > 8192",
        "TestSnapshotsPostgresWholeSourceValidityKeepsChargeTenantAndCurrentRead", "",
        "actual source validity still refuses the complete admitted receipt",
    ),
    "routing-capture-read-support": (
        "internal/store/bgp_routing_capture_reader.go",
        "if err := redactUnreadableCapturedNextHops(ctx, sc, &lookup, budget); err != nil {",
        "if err := error(nil); err != nil {",
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges", "",
        "retained next-hop read reused unavailable support or erased independent paths",
    ),
    "flow-routing-sharing": (
        "internal/store/flowstore/explorer_routing.go",
        "fact := builder.data.facts[id]",
        "fact := builder.data.facts[id]; for name,value:=range row.Fields { if err:=builder.charge(256+int64(len(name)+len(value))*12);err!=nil{return [32]byte{},err} }",
        "TestRoutingQueryProjectionKeepsWholeSharedPathsAndOriginalTenantKeys", "",
        "complete routing query projection lost shared full paths or original references",
    ),
    "flow-capture-read-tenant": (
        "internal/store/flowstore/routing_capture_reads.go",
        "entry.row.TenantID != tenant || entry.row.TS.Before(plan.From)",
        "(false && entry.row.TenantID != tenant) || entry.row.TS.Before(plan.From)",
        "TestRoutingCaptureReferenceReadsKeepCompleteOriginalScopeAndAdmission", "",
        "routing reference read truncated the complete original population",
    ),
    "routing-capture-read-context": (
        "internal/store/bgp_routing_capture_reader.go",
        "if err := authorize(ctx, record); err != nil {",
        "if err := authorize(ctx, record); false && err != nil {",
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges", "",
        "retained routing key bypassed current context authorization",
    ),
    "routing-capture-read-source": (
        "internal/store/bgp_routing_capture_reader.go",
        "if !current {",
        "if false && !current {",
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges", "",
        "retained routing reader reused removed current source authority",
    ),
    "flow-witness-runtime": (
        "cmd/probectl-flow-agent/main.go",
        "func (o observedFlowEvidence) SubmitFlowRouting(",
        "func (o observedFlowEvidence) submitFlowRouting(",
        "TestObservedFlowEvidenceKeepsCompleteRoutingWitnessChannel", "",
        "runtime evidence wrapper dropped the routing witness channel",
    ),
    "routing-intent-publication": (
        "internal/store/bgp_routing_capture_repository.go",
        "func readRoutingCaptureInScope(ctx context.Context, sc tenancy.Scope, key [32]byte, budget BGPRoutingBudget) (routingCaptureReceipt, bool, error) {",
        "func readRoutingCaptureInScope(ctx context.Context, sc tenancy.Scope, key [32]byte, budget BGPRoutingBudget) (routingCaptureReceipt, bool, error) {\n"
        "if intent, found, err := loadRoutingCaptureIntentInScope(ctx,sc,key); err == nil && found { objects,e := readRoutingCaptureIntentPayloadInScope(ctx,sc,intent,budget); if e != nil { return routingCaptureReceipt{},false,e }; return routingCaptureReceipt{key:key,capturedAt:intent.capturedAt,outcome:\"captured\",objects:objects},true,nil }\n",
        "TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone", "",
        "unattested private candidate became canonical routing evidence",
    ),
    "routing-intent-clock": (
        "internal/store/bgp_routing_capture_intents.go",
        "return intent.reference(), err",
        "_ = intent; return BGPRoutingCaptureReference{Key:key,CapturedAt:objects.capturedAt}, err",
        "TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone", "",
        "provisional retry replaced its first processing clock",
    ),
    "routing-intent-generation": (
        "internal/store/bgp_routing_capture_intents.go",
        "sourceepoch.MatchSourceGenerationInScope(ctx, sc, generation)",
        "error(nil)",
        "TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone", "",
        "pre-erasure provisional capture republished source data",
    ),
    "routing-intent-epoch-final": (
        "internal/store/bgp_routing_capture_finalization.go",
        "if intent.sourceGeneration == generation {",
        "if true {",
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges", "",
        "expired provisional epoch became canonical after erasure",
    ),
    "routing-intent-current-source": (
        "internal/store/bgp_routing_capture_finalization.go",
        "current, err := routingCapturePublicationCurrent(ctx, sc, lookup, sender, input, budget)",
        "_ = lookup; current, err := true, error(nil)",
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges", "",
        "revoked source finalized a private provisional capture",
    ),
    "routing-intent-refill": (
        "internal/store/bgp_routing_capture_intents.go",
        "if intent, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, key); err != nil || exists {\n\t\treturn intent.reference(), err\n\t}",
        "if intent, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, key); err != nil || exists {\n"
        "if err == nil && exists { var linked bool; err=sc.Q.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM bgp_flow_capture_intent_payloads WHERE tenant_id=$1 AND flow_key=$2)`,sc.Tenant.String(),key[:]).Scan(&linked); if err==nil && !linked { err=insertRoutingCaptureObjects(ctx,sc,objects); if err==nil { _,err=sc.Q.Exec(ctx,`INSERT INTO bgp_flow_capture_intent_payloads(tenant_id,flow_key,facts_digest,clocks_digest) VALUES($1,$2,$3,$4)`,sc.Tenant.String(),key[:],objects.facts.digest[:],objects.clocks.digest[:]) } } }; return intent.reference(),err\n}",
        "TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone", "",
        "erased provisional retry refilled its payload or changed first clock",
    ),
    "flow-capture-consumer-wire": (
        "internal/pipeline/flow_capture.go",
        'ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))',
        'ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant)); for _, record := range records { record.TenantId = tenant }',
        "TestFlowCaptureConsumerKeepsOriginalDigestFrozenClockAndTenant", "",
        "capture consumer lost verified tenant or original raw digest before enrichment",
    ),
    "flow-capture-consumer-key": (
        "internal/pipeline/flow_capture.go",
        'ref.Key != projection.key || clock <= 0',
        '(false && ref.Key != projection.key) || clock <= 0',
        "TestFlowCaptureConsumerRefusesPartialUnscopedAndMismatchedResolution", "wrong-key",
        "partial or foreign capture batch reached storage or was acknowledged",
    ),
    "flow-capture-consumer-budget": (
        "internal/pipeline/flow_capture.go",
        'memory -= cost * 4',
        '_ = cost',
        "TestFlowCaptureConsumerRefusesPartialUnscopedAndMismatchedResolution", "aggregate-memory",
        "partial or foreign capture batch reached storage or was acknowledged",
    ),
    "flow-capture-row-identity": (
        "internal/store/flowstore/clickhouse.go",
        'if r.RoutingCaptureKey != "" {',
        'if false && r.RoutingCaptureKey != "" {',
        "TestFlowRoutingCaptureRowsPreserveRawIdentityAndTenant", "",
        "original raw identity changed with retry enrichment",
    ),
    "flow-capture-row-scope": (
        "internal/store/flowstore/routing_capture.go",
        'err != nil || row.RoutingCaptureKey != hex.EncodeToString(key[:])',
        'err != nil || (false && row.RoutingCaptureKey != hex.EncodeToString(key[:]))',
        "TestFlowRoutingCaptureRowsRefuseIncompleteOrForeignMetadata", "",
        "incomplete or foreign routing reference reached flow storage",
    ),
    "flow-capture-clock": (
        "internal/pipeline/flow.go",
        "func rowFromProtoAt(f *flowv1.FlowRecord, now time.Time) flowstore.Row {",
        "func rowFromProtoAt(f *flowv1.FlowRecord, now time.Time) flowstore.Row { now = time.Now()",
        "TestFlowProjectionUsesFrozenFirstProcessingClock", "",
        "frozen first processing clock changed retry projection or original counters",
    ),
    "flow-identity-complete": (
        "internal/flow/entity_evidence.go",
        "source := entity.SourceKey{AgentID: c.cfg.AgentID, Kind: entity.FlowExporter,",
        "if len(claims) == 64 { break }; source := entity.SourceKey{AgentID: c.cfg.AgentID, Kind: entity.FlowExporter,",
        "TestFlowEvidencePreservesEveryConfiguredDomainBeyondTransportAndCachePages", "",
        "complete configured source batch lost identity evidence",
    ),
    "flow-identity-scan": (
        "internal/flow/entity_evidence.go",
        "seen[key] = struct{}{}",
        "if len(seen) >= 4096 { break }; seen[key] = struct{}{}",
        "TestFlowEvidencePreservesEveryConfiguredDomainBeyondTransportAndCachePages", "",
        "complete configured source batch lost identity evidence",
    ),
    "flow-witness-producer": (
        "internal/flow/routing_evidence.go",
        "record.TenantID != c.cfg.TenantID || record.AgentID != c.cfg.AgentID",
        "false && (record.TenantID != c.cfg.TenantID || record.AgentID != c.cfg.AgentID)",
        "TestFlowRoutingWitnessProducerRefusesForeignUnconfiguredAndPartialMetadata", "",
        "foreign or malformed source exposed partial routing witnesses",
    ),
    "flow-witness-issued": (
        "internal/agenttransport/entity_evidence.go",
        "if !known {",
        "if false && !known {",
        "TestFlowRoutingWitnessRealMTLSKeepsTenantFirstReceiptAndCurrentSender", "",
        "unissued evidence serial reached a routing witness",
    ),
    "flow-witness-client": (
        "internal/agent/flow_routing_capture.go",
        "!bytes.Equal(capture.Key, expected[i][:])",
        "(!bytes.Equal(capture.Key, expected[i][:]) && false)",
        "TestFlowRoutingClientRequiresCompleteOrderedCertifiedReceipts", "",
        "flow witness client accepted mixed foreign or partial receipt",
    ),
    "flow-witness-receiver": (
        "internal/agenttransport/flow_routing_capture.go",
        "len(raw.RawDigest) != 32 || len(raw.ProtoReflect().GetUnknown()) != 0",
        "len(raw.RawDigest) != 32 || false && len(raw.ProtoReflect().GetUnknown()) != 0",
        "TestFlowRoutingWitnessReceiverRefusesMixedMalformedAndUnknownAuthority", "",
        "malformed or authority-bearing witness exposed a partial batch",
    ),
    "routing-capture-bus": (
        "internal/store/bgp_routing_capture_service.go",
        "key, err := service.captureKey(ctx, claimedSender, rawDigest, input, budget)",
        "if rawDigest != ([32]byte{}) { return service.CaptureAuthenticated(ctx, claimedSender, rawDigest, input, budget) }; key, err := service.captureKey(ctx, claimedSender, rawDigest, input, budget)",
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges", "",
        "bus claimed sender created a positive canonical capture",
    ),
    "flow-capture-wire": (
        "internal/flow/routing_capture.go",
        "body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(record)",
        "copyForOmission := proto.Clone(record).(*flowv1.FlowRecord); copyForOmission.SourceAsName = \"\"; body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(copyForOmission)",
        "TestRoutingCaptureWitnessBindsEveryOriginalFieldAndUnknownWireData", "source_as_name",
        "original flow field escaped capture identity",
    ),
    "flow-capture-budget": (
        "internal/flow/routing_capture.go",
        "if memoryBytes <= 0 || workUnits <= 0 || size <= 0 || size > memoryBytes/4 || size > workUnits/8 {",
        "if false && (memoryBytes <= 0 || workUnits <= 0 || size <= 0 || size > memoryBytes/4 || size > workUnits/8) {",
        "TestRoutingCaptureWitnessPreservesCompleteValuesAndRefusesPartialAdmission", "",
        "refused capture exposed a partial witness",
    ),
    "routing-capture-sender": (
        "internal/store/bgp_routing_flow.go",
        'if authenticatedSender != "" && owner.AgentID != authenticatedSender {',
        'if false && authenticatedSender != "" && owner.AgentID != authenticatedSender {',
        "TestRoutingCaptureServiceSealsCurrentExporterBeforeRetriesAndSourceChanges", "",
        "authenticated sender selected another agent's canonical router",
    ),
    "routing-capture-subject": (
        "internal/tenantlife/flow_query_subject.go",
        ' || table == "bgp_flow_capture_objects"',
        "",
        "TestRoutingCaptureSubjectDecodedErasureKeepsFirstReceiptAndSibling", "",
        "decoded routing capture subject export lost its own content or crossed tenant",
    ),
    "routing-capture-first": (
        "internal/store/bgp_routing_capture_repository.go",
        "if err != nil || exists {",
        "if err != nil { _ = exists",
        "TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone", "",
        "retry changed the first successful routing capture",
    ),
    "routing-capture-generation": (
        "internal/store/bgp_routing_capture_repository.go",
        "sourceepoch.MatchSourceGenerationInScope(ctx, sc, sourceGeneration)",
        "func() error { _ = sourceGeneration; _ = sourceepoch.ErrInvalidating; return nil }()",
        "TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone", "",
        "pre-erasure routing capture republished source data",
    ),
    "routing-capture-state": (
        "internal/store/bgp_routing_capture_repository.go",
        "admitRetainedRoutingCapture(ctx, sc, objects, budget)",
        "error(nil)",
        "TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone", "",
        "retained capture ignored complete tenant state admission",
    ),
    "routing-capture-scope": (
        "internal/store/bgp_routing_capture.go",
        "if source.Scope != owner.Scope || source.RouterID != owner.RouterID {",
        "if false && source.Scope != owner.Scope || source.RouterID != owner.RouterID {",
        "TestRoutingCaptureObjectsRejectRehashedSemanticAndTenantCorruption", "foreign-route",
        "rehashed invalid capture exposed facts",
    ),
    "routing-capture-projection": (
        "internal/store/bgp_routing_capture.go",
        "if !reflect.DeepEqual(fields, side.Fields) {",
        "if false && !reflect.DeepEqual(fields, side.Fields) {",
        "TestRoutingCaptureObjectsRejectRehashedSemanticAndTenantCorruption", "path-text",
        "rehashed invalid capture exposed facts",
    ),
    "routing-next-hop-as": (
        "internal/store/bgp_routing_next_hop.go",
        "if !exists {\n\t\t\tunresolved = true\n\t\t\tcontinue\n\t\t}",
        "if !exists { group = routingNextHopPeer{asn:65010, validUntil:time.Now().Add(time.Hour)} }",
        "TestRoutingNextHopASRequiresActualUniqueNeighborAndCompleteProvenance", "",
        "next-hop AS was guessed from path or a different peer",
    ),
    "routing-next-hop-expiry": (
        "internal/store/bgp_routing_next_hop.go",
        "if field.ASN != nil && !field.ValidUntil.After(at) {",
        "if false && field.ASN != nil && !field.ValidUntil.After(at) {",
        "TestRoutingNextHopASRequiresActualUniqueNeighborAndCompleteProvenance", "",
        "expired next-hop observation retained an ASN or provenance",
    ),
    "routing-path-origin-set": (
        "internal/bgp/routing_path_fields.go",
        "if segment.Kind == ASPathSequence {\n\t\t\tvalue := segment.Values[len(segment.Values)-1]",
        "if segment.Kind == ASPathSequence || segment.Kind == ASPathSet {\n\t\t\tvalue := segment.Values[len(segment.Values)-1]",
        "TestRoutingPathFieldsKeepCompleteSemanticsAndExplicitUnknowns", "origin-set",
        "routing field projection lost complete semantics or explicit unknowns",
    ),
    "routing-path-complete": (
        "internal/bgp/routing_path_fields.go",
        "Values: append([]uint32(nil), segment.Values...)",
        "Values: append([]uint32(nil), segment.Values[:min(8192,len(segment.Values))]...)",
        "TestRoutingPathFieldsKeepCompleteSemanticsAndExplicitUnknowns", "",
        "admitted complete reconstructed path was truncated by a former count",
    ),
    "routing-flow-protocol": (
        "internal/store/bgp_routing_flow.go",
        " && binding.Protocol == input.Protocol && binding.Domain == input.Domain",
        "",
        "TestRoutingFlowCaptureRequiresUniqueCurrentExporterAndKeepsTenantRoutes", "",
        "unattested flow protocol/domain received a router path",
    ),
    "routing-flow-owner": (
        "internal/store/bgp_routing_flow.go",
        'if matches != 1 || selected.RouterID == "" {',
        'if matches == 0 || selected.RouterID == "" {',
        "TestRoutingFlowCaptureCannotChooseOwnerFromPayloadOrPartialEvidence", "",
        "ambiguous or foreign exporter selected canonical routing ownership",
    ),
    "routing-disjoint-cohort": (
        "internal/store/bgp_routing_stage.go",
        "if err := retireRoutingStageCohorts(ctx, sc, source, input.Definitions); err != nil {",
        "if _, err := invalidateRoutingStageSource(ctx, sc, source); err != nil {",
        "TestRoutingStageKeepsDisjointCohortsAndRetiresWholeOverlap", "",
        "disjoint IPv6 Peer Up retired IPv4 or another tenant",
    ),
    "routing-mapped-selector": (
        "internal/store/bgp_routing_stream.go",
        "if err := routingStreamSelectorMatches(source, input.PeerSelector); err != nil {",
        "if err := error(nil); err != nil {",
        "TestRoutingMappedVRFRequiresCurrentBindingThroughRealMTLS", "",
        "unbound routing UPDATE changed canonical global state",
    ),
    "routing-native-metadata": (
        "internal/control/mcp_bgp_routing_bindings.go",
        "return marshalBGPRoutingMCPConfiguration(raw)", "return raw, nil",
        "TestBGPRoutingBindingsStdioKeepsTenantEpochAndCurrentCredentials", "2026-07-28",
        "native routing metadata changed canonical binding identity",
    ),
    "routing-api-current-authority": (
        "internal/control/bgp_routing_api.go",
        "authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)",
        "authority, err := &currentUserAuthority{principal: actor}, error(nil)",
        "TestBGPRoutingConfigurationAPIKeepsTenantCurrentActorEpochAndAtomicAudit", "",
        "served routing read bypassed current mapped-context policy",
    ),
    "routing-api-atomic-audit": (
        "internal/control/bgp_routing_api.go",
        'return s.recordAudit(ctx, sc, r.WithContext(ctx), "bgp.routing_bindings.replaced", input.SourceRef,\n\t\t\tmap[string]any{"collector_agent_id": input.CollectorAgentID, "context_id": out.ContextID, "epoch": out.Manifest.Epoch, "binding_count": len(out.Manifest.Bindings)})',
        "return nil",
        "TestBGPRoutingConfigurationAPIKeepsTenantCurrentActorEpochAndAtomicAudit", "",
        "routing audit failure committed a source replacement",
    ),
    "routing-configuration-current-policy": (
        "internal/store/bgp_routing_configuration.go",
        "if config.Manifest != nil {", "if false && config.Manifest != nil {",
        "TestRoutingOperatorConfigurationKeepsTenantPolicyCASAndAtomicAudit", "",
        "routing configuration disclosed a denied current target",
    ),
    "routing-configuration-proposed-policy": (
        "internal/store/bgp_routing_configuration.go",
        "for _, binding := range replacement {", "for _, binding := range []BGPRoutingBinding(nil) {",
        "TestRoutingOperatorConfigurationKeepsTenantPolicyCASAndAtomicAudit", "",
        "routing replacement bypassed proposed target authorization",
    ),
    "routing-lookup-source-format": (
        "internal/store/bgp_routing_lookup.go",
        "COALESCE(peer_identity->>'SourceFormat','')=$13",
        "$13::text IS NOT NULL",
        "TestRoutingBoundSerializerLookupRefusesChangedRetainedFormat", "",
        "routing lookup accepted a changed retained serializer",
    ),
    "routing-source-profile-current": (
        "internal/store/bgp_routing_decode.go",
        "profile, err := routingDecodeProfile(ctx, sc, base, input.RefusedPeer, budget)",
        "profile, err := BGPRoutingDecodeProfile{}, error(nil); _ = base",
        "TestRoutingFRRProfileRequiresCurrentOperatorBindingThroughRealMTLS", "",
        "real mTLS routing staging lost complete owned source",
    ),
    "routing-retained-source-format": (
        "internal/store/bgp_routing_bound_authority.go",
        "definition.Peer.SourceFormat != selected.Binding.SourceFormat",
        "false",
        "TestRoutingBoundSerializerKeepsCurrentFormatAndCompleteFamilyCohort", "",
        "wrong routing peer reached source decoder",
    ),
    "routing-peer-up-rate-refusal": (
        "internal/agenttransport/bgp_routing_stage.go",
        "var result store.BGPRoutingStageResult",
        'if !admitted { return nil, status.Error(codes.ResourceExhausted, "tenant routing evidence rate exceeded") }; var result store.BGPRoutingStageResult',
        "TestRoutingPeerUpRateRefusalInvalidatesOnlyItsCurrentOwnedSource", "",
        "rate-refused routing Peer Up retained stale or foreign current state",
    ),
    "routing-malformed-unbound": (
        "internal/agenttransport/bgp_routing_stage.go",
        "if unbound {", "if false && unbound {",
        "TestRoutingMalformedUnboundPeerUpPreservesKnownContexts", "",
        "truncated unbound routing selector retired a known canonical context",
    ),
    "routing-refused-selector": (
        "internal/store/bgp_routing_stage_binding.go",
        "if input.RefusedPeer != nil {", "if false && input.RefusedPeer != nil {",
        "TestRoutingBoundStagingKeepsSelectorIncarnationsAndSourceWideRefusal", "",
        "selector refusal retired sibling bindings or created routing authority",
    ),
    "routing-bound-stream-unwired": (
        "internal/store/bgp_routing_stream.go",
        "source, handled, err := resolveRoutingStreamSource(ctx, sc, source, input, profile)",
        "source, handled, err := source, false, error(nil)",
        "TestRoutingBoundStreamKeepsWholeCurrentGenerationsAndRefusalIsolation",
        "",
        "bound source message refused current complete generation",
    ),
    "routing-bound-stream-generation": (
        "internal/store/bgp_routing_stage_binding.go",
        "AND ($6::uuid IS NULL OR generation=$6::uuid)",
        "AND ($6::uuid IS NULL OR $6::uuid IS NOT NULL)",
        "TestRoutingBoundStreamKeepsWholeCurrentGenerationsAndRefusalIsolation",
        "",
        "known routing admission refusal retained or crossed a source generation",
    ),
    "routing-bound-stream-cohort": (
        "internal/store/bgp_routing_stream_binding.go",
        "if !routingStreamFamiliesComplete(source, seen) {",
        "if false && !routingStreamFamiliesComplete(source, seen) {",
        "TestRoutingBoundStreamKeepsWholeCurrentGenerationsAndRefusalIsolation",
        "",
        "incomplete retained source refreshed a surviving routing view",
    ),
    "routing-bound-stream-peer": (
        "internal/store/bgp_routing_stream.go",
        "if !routingStreamPeerMatchesSource(source, current, ref.AFI, ref.SAFI) {",
        "if false && !routingStreamPeerMatchesSource(source, current, ref.AFI, ref.SAFI) {",
        "TestRoutingBoundStreamKeepsWholeCurrentGenerationsAndRefusalIsolation",
        "",
        "wrong routing peer reached source decoder",
    ),
    "routing-stage-selector": (
        "internal/store/bgp_routing_stage.go",
        "AND source_kind='router_bmp' AND state IN ('staging','current')\n AND ((routing_selection IS NULL AND $6::text IS NULL)\n      OR (routing_selection->>'epoch'=$6 AND routing_selection->>'binding_id'=$7))",
        "AND source_kind='router_bmp' AND state IN ('staging','current') AND ($6::text IS NULL OR $6::text IS NOT NULL) AND ($7::text IS NULL OR $7::text IS NOT NULL)",
        "TestRoutingBoundStagingKeepsSelectorIncarnationsAndSourceWideRefusal",
        "",
        "routing source selector retired a sibling binding or tenant",
    ),
    "routing-stage-nonce": (
        "internal/store/bgp_routing_stage.go",
        "if conflict, err := routingStageNonceConflicts(ctx, sc, source, input.ObservationID); err != nil || conflict {",
        "if conflict, err := false, error(nil); err != nil || conflict {",
        "TestRoutingBoundStagingKeepsSelectorIncarnationsAndSourceWideRefusal",
        "",
        "former routing observation UUID borrowed a replacement binding",
    ),
    "routing-stage-base-credential": (
        "internal/store/bgp_routing_stage_binding.go",
        "if _, err := routingCredentialAuthority(ctx, sc, base, true, metadata.Epoch); err != nil {",
        "if _, err := (BGPRoutingSourceAuthority{}), error(nil); err != nil {",
        "TestRoutingBoundStagingKeepsSelectorIncarnationsAndSourceWideRefusal",
        "",
        "foreign credential authorized routing source-wide invalidation",
    ),
    "routing-stage-base-clock": (
        "internal/store/bgp_routing_stage_binding.go",
        "AND collector_context_id=$4 AND observed_at<=$5",
        "AND collector_context_id=$4 AND $5::timestamptz IS NOT NULL",
        "TestRoutingBoundStagingKeepsSelectorIncarnationsAndSourceWideRefusal",
        "",
        "queued old invalidation retired a newer routing source",
    ),
    "routing-stage-complete-peer": (
        "internal/store/bgp_routing_stage.go",
        "if completePeer != nil && !bytes.Equal(completePeer, metadata) {",
        "if false && completePeer != nil && !bytes.Equal(completePeer, metadata) {",
        "TestRoutingBoundStagingKeepsSelectorIncarnationsAndSourceWideRefusal",
        "",
        "mixed complete routing peers were staged as one generation",
    ),
    "routing-stage-families": (
        "internal/store/bgp_routing_stage.go",
        "if err := retireRoutingStageCohorts(ctx, sc, source, input.Definitions); err != nil {",
        "if err := error(nil); err != nil {",
        "TestRoutingStageReplacementWithdrawsOmittedFamiliesWithoutAffectingSibling",
        "",
        "replacement routing peer retained an omitted address family",
    ),
    "routing-selection-unknown": (
        "internal/store/bgp_routing_bound_authority.go",
        "decoder.DisallowUnknownFields()",
        "_ = decoder",
        "TestRoutingSelectionReaderRefusesUnknownBorrowedAndIncompleteBindings",
        "",
        "stored routing selection accepted unknown authority metadata",
    ),
    "routing-bound-read": (
        "internal/store/bgp_routing_router.go",
        "view_kind IN ('loc_rib','operator_loc_rib')",
        "view_kind='loc_rib'",
        "TestBGPRoutingBoundAuthorityKeepsBaseCredentialsEpochBirthAndTenant",
        "",
        "bound routing lookup lost current owned path",
    ),
    "routing-managed-generated": (
        "ee/silo/provisioner.go",
        "CASE WHEN a.attgenerated='s' THEN c.generation_expression ELSE '' END",
        "''",
        "TestBGPRoutingBindingStorageKeepsManagedHybridAndOldSchemaBoundaries",
        "siloed",
        "silo catch-up lost routing collector computation",
    ),
    "routing-managed-collector": (
        "ee/silo/bgp_routing_plan.go",
        '{"bgp_routing_views", "fx5_route_view_collector_context_fk",',
        '{"", "fx5_route_view_collector_context_fk",',
        "TestBGPRoutingBindingStorageKeepsManagedHybridAndOldSchemaBoundaries",
        "siloed",
        "routing target borrowed an unassigned foreign collector context",
    ),
    "routing-bound-view": (
        "internal/store/bgp_routing_updates.go",
        "AND routing_selection IS NOT DISTINCT FROM $10::jsonb",
        "AND $10::jsonb IS NOT NULL",
        "TestBGPRoutingBoundAuthorityKeepsBaseCredentialsEpochBirthAndTenant",
        "",
        "routing writer accepted a generation with different stored binding",
    ),
    "routing-bound-origin": (
        "internal/store/bgp_routing_authority.go",
        "AND origin.revoked_at IS NULL",
        "AND true",
        "TestBGPRoutingBoundAuthorityKeepsBaseCredentialsEpochBirthAndTenant",
        "origin-revoked",
        "bound routing view retained changed credential or target authority",
    ),
    "routing-legacy-authority-control": (
        "internal/store/bgp_routing_authority.go",
        " AND source.routing_epoch IS NULL",
        " AND true",
        "TestRoutingBindingManifestRefusesLegacyAuthorityWithoutChangingOtherTenant",
        "",
        "explicit routing manifest restored legacy source authority",
    ),
    "routing-binding-current": (
        "internal/store/bgp_routing_binding_lookup.go",
        "source.routing_epoch=$9 AND source.routing_assigned_at=$4",
        "$9::uuid IS NOT NULL AND source.routing_assigned_at=$4",
        "TestRoutingBindingManifestKeepsTenantEpochTargetsAndWholeAdmission",
        "", "cached routing selector borrowed a replacement epoch",
    ),
    "routing-binding-record": (
        "internal/store/bgp_routing_binding_lookup.go",
        "AND binding=$14::jsonb",
        "AND $14::jsonb IS NOT NULL",
        "TestRoutingBindingManifestKeepsTenantEpochTargetsAndWholeAdmission",
        "", "cached routing selector ignored changed stored metadata",
    ),
    "routing-binding-birth": (
        "internal/store/bgp_routing_binding_lookup.go",
        "AND router.created_at<=$4 AND target.created_at<=$4",
        "AND $4::timestamptz IS NOT NULL",
        "TestRoutingBindingManifestKeepsTenantEpochTargetsAndWholeAdmission",
        "", "recreated routing target borrowed an old operator binding",
    ),
    "routing-binding-legacy": (
        "internal/store/bgp_routing_bindings.go",
        "WHERE tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND source_kind IN ('router_bmp','router_bmp_bound')",
        "WHERE false AND tenant_id=$1 AND collector_agent_id=$2 AND source_ref=$3 AND source_kind IN ('router_bmp','router_bmp_bound')",
        "TestRoutingBindingManifestKeepsTenantEpochTargetsAndWholeAdmission",
        "", "new routing manifest retained a legacy current view or invalidated another tenant",
    ),
    "routing-binding-epoch": (
        "internal/store/bgp_routing_bindings.go",
        'if current == nil && ifMatch != "" || current != nil && *current != ifMatch {',
        'if false && (current == nil && ifMatch != "" || current != nil && *current != ifMatch) {',
        "TestRoutingBindingManifestKeepsTenantEpochTargetsAndWholeAdmission",
        "", "stale routing editor replaced a current binding",
    ),
    "routing-rate-refusal": (
        "internal/agenttransport/bgp_routing_message.go",
        "Reset: !admitted || raw.SourceReset",
        "Reset: raw.SourceReset",
        "TestRoutingStagingRealMTLSKeepsTenantOriginRetryAndPrivateState",
        "", "rate-refused routing frame retained stale or foreign current state",
    ),
    "routing-stream-atomic": (
        "internal/store/bgp_routing_stream.go",
        "ROLLBACK TO SAVEPOINT routing_stream_message",
        "RELEASE SAVEPOINT routing_stream_message",
        "TestBGPRoutingWholeStreamKeepsFamilyAtomicityReplayAndTenantFence",
        "", "late family fault left a partial retained path",
    ),
    "routing-stage-context": (
        "internal/store/bgp_routing_stage.go",
        "if definition.Peer.Distinguisher != ([8]byte{}) {",
        "if false && definition.Peer.Distinguisher != ([8]byte{}) {",
        "TestBGPRoutingStagingKeepsTenantRetryLeaseAndAtomicCompletePeer",
        "", "unbound routing VRF changed storage context",
    ),
    "routing-stage-atomic": (
        "internal/store/bgp_routing_stage.go",
        "ROLLBACK TO SAVEPOINT routing_peer_up_stage",
        "RELEASE SAVEPOINT routing_peer_up_stage",
        "TestBGPRoutingStagingKeepsTenantRetryLeaseAndAtomicCompletePeer",
        "", "late routing family fault escaped whole-source rollback",
    ),
    "routing-stage-retry": (
        "internal/store/bgp_routing_stage.go",
        "peer_identity=$5::jsonb AND observed_at=$6::timestamptz",
        "$5::jsonb IS NOT NULL AND observed_at=$6::timestamptz",
        "TestBGPRoutingStagingKeepsTenantRetryLeaseAndAtomicCompletePeer",
        "", "altered routing retry retained current state or damaged another tenant",
    ),
    "routing-router-conflict": (
        "internal/store/bgp_routing_router.go",
        "if count != 1 {",
        "if false && count != 1 {",
        "TestBGPRoutingRouterLookupUsesOwnContextAndRefusesConflictingCompleteViews",
        "", "conflicting router views selected a convenient route",
    ),
    "routing-lookup-view": (
        "internal/store/bgp_routing_lookup.go",
        "AND view_kind=$11 AND NOT filtered",
        "AND $11::text IS NOT NULL AND NOT filtered",
        "TestBGPRoutingLookupKeepsLongestPrefixEveryPathTenantFamilyAndSelectedView",
        "", "adjacent route view impersonated a selected router lookup",
    ),
    "routing-lookup-birth": (
        "internal/store/bgp_routing_lookup.go",
        "birth.ObservedAt = view.born",
        "birth.ObservedAt = source.ObservedAt",
        "TestBGPRoutingLookupRefusesChangedAuthorityClockCorruptionAndMixedSnapshots",
        "source-rebound", "changed routing authority or corrupt path retained attribution",
    ),
    "routing-write-lock": (
        "internal/store/bgp_routing_authority.go",
        "query += ` FOR SHARE OF sender,origin,assignment,source,router`",
        "query += ``",
        "TestBGPRoutingWritesSerializeSourceChangesAndRejectStaleSnapshots",
        "sender", "source mutation escaped routing write lock",
    ),
    "routing-quota-snapshot": (
        "internal/store/bgp_routing_views.go",
        'if isolation != "read committed" {',
        'if false && isolation != "read committed" {',
        "TestBGPRoutingQuotaWaitUsesFreshTenantAccountAndRefusesOldSnapshots",
        "", "routing quota accepted a potentially stale transaction snapshot",
    ),
    "routing-batch-invalidation": (
        "internal/store/bgp_routing_updates.go",
        "SET state='invalid',updated_at=clock_timestamp()",
        "SET state=state,updated_at=clock_timestamp()",
        "TestBGPRoutingBatchesKeepCompleteTenantPathsReplayWithdrawalAndPublication",
        "", "routing batch mixed tenant, initial view or complete path population",
    ),
    "routing-birth-epoch": (
        "internal/store/bgp_routing_updates.go",
        "birth.ObservedAt = view.born",
        "birth.ObservedAt = source.ObservedAt\n\t_ = view.born",
        "TestBGPRoutingBatchRefusalInvalidatesWithoutPartialWritesOrEpochRevival",
        "", "new source assignment revived a former routing generation",
    ),
    "routing-final-authority": (
        "internal/store/bgp_routing_updates.go",
        "if err := store.checkRoutingWriteLease(ctx, sc, birth, view.validUntil); err != nil {",
        "if err := error(nil); err != nil {",
        "TestBGPRoutingBatchRollsBackLateStorageFaultAndOriginExpiry",
        "origin-expiry", "routing batch acknowledged a late store fault or expired origin",
    ),
    "routing-source-reset": (
        "internal/store/bgp_routing_updates.go",
        'return invalidateRoutingView(ctx, sc, source, ref, "source-reset")',
        'return BGPRoutingApplyResult{Status: "invalidated", Reason: "source-reset"}, nil',
        "TestBGPRoutingResetClosesKnownGenerationBeforeRefusedReplacement",
        "", "refused replacement revived a reset routing generation or changed its sibling",
    ),
    "routing-heartbeat-gap": (
        "internal/store/bgp_routing_updates.go",
        "if batch.Sequence != view.nextSequence {",
        "if false && batch.Sequence != view.nextSequence {",
        "TestBGPRoutingHeartbeatKeepsIncarnationSequenceClockAndTenantLease",
        "", "routing heartbeat result differs",
    ),
    "routing-heartbeat-clock": (
        "internal/store/bgp_routing_updates.go",
        "batch.ObservedAt.Before(*view.lastObservedAt)",
        "batch.ObservedAt.Before(view.born)",
        "TestBGPRoutingMessageClockRejectsLegacyWritersAndUnusableHeartbeats",
        "clock-regression", "unusable routing heartbeat retained former attribution",
    ),
    "routing-missing-clock": (
        "internal/store/bgp_routing_updates.go",
        'return invalidateRoutingView(ctx, sc, source, ref, "unavailable-message-clock")',
        "view.lastObservedAt = &view.born; sequence := view.lastSequence; view.clockSequence = &sequence",
        "TestBGPRoutingMessageClockRejectsLegacyWritersAndUnusableHeartbeats",
        "legacy-clock", "unusable routing heartbeat retained former attribution",
    ),
}


def routing_control_package(root):
    matches = {package for suite in (UNIT, INTEGRATION)
               for package, roots in suite.items() if root in roots}
    if len(matches) != 1:
        raise RuntimeError("routing control must name one registered test package: " + root)
    return matches.pop()


def bgp_routing_write_controls():
    out = Path("artifacts/interface-prefix-transport").resolve()
    for name, (file, seam, replacement, root, child, marker) in ROUTING_WRITE_CONTROLS.items():
        source = Path(file).resolve()
        original = source.read_text()
        assert original.count(seam) == (2 if name in ("routing-final-authority", "routing-birth-epoch") else 1)
        mutant = overlay_source_path(out, name + ".go")
        mutant.write_text(original.replace(seam, replacement))
        overlay = out / (name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
        package = routing_control_package(root)
        result = execute(package, (root,), name, integration=True,
                         overlay=overlay, child=child)
        if not report_regression_failed_on_assertion(
            result.stdout, result.returncode, package=PREFIX + package,
            root=root, child=child, marker=marker,
        ):
            raise RuntimeError(name + " did not fail its exact assertion")


def configuration_incarnation_controls():
    source = Path("internal/store/interface_role_configuration.go").resolve()
    original = source.read_text()
    root = "TestInterfaceRoleConfigurationPostgresKeepsTenantCASAndOverrideIncarnations"
    out = Path("artifacts/interface-prefix-transport").resolve()
    for name, start, end, clause, marker in (
        (
            "policy",
            "func (s InterfaceRoleConfiguration) PutPolicy(",
            "func sameInterfaceRolePolicy(",
            "AND id=$3 AND revision=$4",
            "stale role policy incarnation replaced recreated configuration",
        ),
        (
            "override",
            "func (s InterfaceRoleConfiguration) PutOverride(",
            "func (InterfaceRoleConfiguration) ResetOverride(",
            "AND id=$4 AND revision=$5",
            "stale override incarnation replaced reset configuration",
        ),
    ):
        a, b = original.index(start), original.index(end)
        section = original[a:b]
        assert section.count("previous.ID != expectedID || ") == 1
        assert section.count(clause) == 1
        mutant = section.replace("previous.ID != expectedID || ", "")
        parameter = "$3" if name == "policy" else "$4"
        mutant = mutant.replace(
            clause,
            f"AND {parameter}::uuid IS NOT NULL AND revision="
            + ("$4" if name == "policy" else "$5"),
        )
        path = overlay_source_path(out, name + "_incarnation_omitted.go")
        path.write_text(original[:a] + mutant + original[b:])
        overlay = out / (name + "_incarnation_omitted.json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
        result = execute(
            "internal/store",
            (root,),
            name + "_incarnation_omitted",
            integration=True,
            overlay=overlay,
        )
        if not report_regression_failed_on_assertion(
            result.stdout,
            result.returncode,
            package=PREFIX + "internal/store",
            root=root,
            child="",
            marker=marker,
        ):
            raise RuntimeError(
                f"omitted {name} incarnation guard did not fail its exact stale-write assertion"
            )
    print(json.dumps({"role_configuration_incarnation_controls": True}))


def configuration_raw_cli_body_control():
    source = Path("internal/cli/generic.go").resolve()
    original = source.read_text()
    profile = 'profile := surfaceCommands["interface-roles"].Ops["set-policy"]\n\t\t'
    assignment = "op.ExactJSON, op.MaxBodyBytes = profile.ExactJSON, profile.MaxBodyBytes"
    seam = profile + assignment
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    path = overlay_source_path(out, "raw_cli_policy_old_quota.go")
    path.write_text(original.replace(seam, profile + "op.ExactJSON = profile.ExactJSON"))
    overlay = out / "raw_cli_policy_old_quota.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
    root = "TestInterfaceRoleCompletePolicyReachesNamedRawCLIAndGeneratedSDK"
    result = execute(
        "internal/cli", (root,), "raw_cli_policy_old_quota", overlay=overlay
    )
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        package=PREFIX + "internal/cli",
        root=root,
        child="",
        marker="complete policy was refused by a former CLI body cap",
    ):
        raise RuntimeError(
            "restored raw CLI quota did not fail the complete-body assertion"
        )
    print(json.dumps({"role_raw_cli_policy_body_control": True}))


def configuration_missing_source_control():
    source = Path("internal/control/interface_roles.go").resolve()
    original = source.read_text()
    offset = original.index("func validateInterfaceRoleSourcePresence(")
    section = original[offset:]
    assert section.count("\t\treturn nil") == 1
    mutant = original[:offset] + section.replace(
        "\t\treturn nil", "\t\treturn errInterfaceRoleInput", 1
    )
    out = Path("artifacts/interface-prefix-transport").resolve()
    path = overlay_source_path(out, "manual_override_old_source_requirement.go")
    path.write_text(mutant)
    overlay = out / "manual_override_old_source_requirement.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
    root = "TestInterfaceRoleOwnedManualOverrideDoesNotInventSourceFreshness"
    result = execute(
        "internal/control",
        (root,),
        "manual_override_old_source_requirement",
        overlay=overlay,
    )
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        package=PREFIX + "internal/control",
        root=root,
        child="",
        marker="missing automatic facts invented a source or role",
    ):
        raise RuntimeError(
            "restored source requirement did not fail the owned unavailable-facts assertion"
        )
    print(json.dumps({"manual_override_without_fabricated_source_control": True}))


def configuration_native_request_control():
    source = Path("internal/ai/mcp/server.go").resolve()
    original = source.read_text()
    seam = "return max(4<<20, s.nativeRenderBudget.SourceBytes)"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    path = overlay_source_path(out, "native_request_old_quota.go")
    path.write_text(original.replace(seam, "return 4<<20"))
    overlay = out / "native_request_old_quota.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
    root = "TestInterfaceRoleNativeToolsPreserveCompleteInputAndUserTenantBoundary"
    result = execute(
        "internal/ai/mcp", (root,), "native_request_old_quota", overlay=overlay
    )
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        package=PREFIX + "internal/ai/mcp",
        root=root,
        child="",
        marker="native policy retained an obsolete envelope ceiling or changed complete tenant input",
    ):
        raise RuntimeError(
            "restored native request quota did not fail the complete-input assertion"
        )
    print(json.dumps({"role_native_request_admission_control": True}))


def configuration_silo_lock_control():
    source = Path("internal/control/interface_role_api.go").resolve()
    original = source.read_text()
    seam = "tenancy.WithSiloTableLock(r.Context())"
    assert original.count(seam) == 2
    out = Path("artifacts/interface-prefix-transport").resolve()
    path = overlay_source_path(out, "role_silo_relation_locks_omitted.go")
    path.write_text(original.replace(seam, "r.Context()"))
    overlay = out / "role_silo_relation_locks_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
    root = "TestInterfaceRoleAPIKeepsSiloRelationsLockedBeforeConfigurationSQL"
    result = execute(
        "ee/silo",
        (root,),
        "role_silo_relation_locks_omitted",
        integration=True,
        overlay=overlay,
    )
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        package=PREFIX + "ee/silo",
        root=root,
        child="",
        marker="role transaction left an unvisited silo configuration table unlocked",
    ):
        raise RuntimeError(
            "omitted silo relation lock did not fail the actual Postgres-lock assertion"
        )
    print(json.dumps({"role_configuration_silo_relation_lock_control": True}))


def configuration_regexp_expansion_control():
    source = Path("internal/control/interface_role_evaluation.go").resolve()
    original = source.read_text()
    start = original.index("func admitInterfaceRoleRegexp(")
    end = original.index("\nfunc interfaceRoleRegexpStates(", start)
    signature = original[start : original.index(" {\n", start)]
    mutant = (
        original[:start] + signature + " {\n\treturn ctx.Err()\n}\n" + original[end:]
    )
    out = Path("artifacts/interface-prefix-transport").resolve()
    path = overlay_source_path(out, "role_regexp_expansion_admission_omitted.go")
    path.write_text(mutant)
    overlay = out / "role_regexp_expansion_admission_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
    root = "TestInterfaceRoleConfiguredEvaluationAdmitsExpansionBeforeCompilation"
    result = execute(
        "internal/control",
        (root,),
        "role_regexp_expansion_admission_omitted",
        overlay=overlay,
    )
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        package=PREFIX + "internal/control",
        root=root,
        child="",
        marker="expanded role regex compiled without complete resource admission",
    ):
        raise RuntimeError(
            "omitted regex admission did not fail its expansion assertion"
        )
    print(json.dumps({"role_regexp_expansion_admission_control": True}))



EXPLANATION_CONTROLS = {
    "stdio-credential": (
        "internal/ai/mcp/stdio.go",
        "return s.ServeStdio(ctx, r, w, p, refresh)",
        "return s.ServeStdio(ctx, r, w, p)",
        "TestInterfaceRoleStdioKeepsWholePoliciesAndRechecksCredentialWithinStream",
        "role stdio current authority mismatch for interface_role_explain",
        "2026-07-28",
    ),
    "stdio-credential-legacy": (
        "internal/ai/mcp/stdio.go",
        "return s.ServeStdio(ctx, r, w, p, refresh)",
        "return s.ServeStdio(ctx, r, w, p)",
        "TestInterfaceRoleStdioKeepsWholePoliciesAndRechecksCredentialWithinStream",
        "role stdio current authority mismatch for interface_role_explain",
        "2025-11-25",
    ),
    "ix-publication": (
        "internal/control/interface_role_explanation_api.go",
        "if !ix.SameGeneration(s.interfaceRoleIXSnapshot(time.Now().UTC())) {",
        "if false && !ix.SameGeneration(s.interfaceRoleIXSnapshot(time.Now().UTC())) {",
        "TestInterfaceRoleExplanationRefusesMidComputationAuthorityChanges",
        "role explanation published after its authority changed",
        "ix-generation",
    ),
    "flow-memory": (
        "internal/control/explorer_flow_roles.go",
        "MemoryBytes: budget.MemoryBytes / 2, WorkUnits: perInterfaceWork",
        "MemoryBytes: budget.MemoryBytes / 4, WorkUnits: perInterfaceWork",
        "TestFlowRoleQueryKeepsCurrentOwnedSourcesAndRefusesPublicationChanges",
        "complete saved policy cannot drive role flow queries under the default profile",
        "",
    ),
    "flow-publication": (
        "internal/control/explorer_flow.go",
        "if err != nil || roleBefore.inputDigest != after.inputDigest || result.RoleDigest != digest || result.RoleTenantID != tenant {",
        "if err != nil || false && (roleBefore.inputDigest != after.inputDigest || result.RoleDigest != digest || result.RoleTenantID != tenant) {",
        "TestFlowRoleQueryKeepsCurrentOwnedSourcesAndRefusesPublicationChanges",
        "role query published stale source metadata after computation",
        "",
    ),
    "flow-grant": (
        "internal/control/explorer_flow_roles.go",
        "current.requestContext(ctx, actor)",
        "(&currentUserAuthority{principal: actor, policies: current.policies}).requestContext(ctx, actor)",
        "TestFlowRoleQueryKeepsCurrentOwnedSourcesAndRefusesPublicationChanges",
        "stale native principal retained role source access",
        "",
    ),
    "flow-frozen": (
        "internal/control/explorer_flow_snapshot_source.go",
        'if !roles && receipt.RoleDigest == "" {',
        'if !roles || receipt.RoleDigest != "" {',
        "TestFlowRoleQueryKeepsCurrentOwnedSourcesAndRefusesPublicationChanges",
        "old frozen role source identity survived reclassification",
        "",
    ),
    "memory": (
        "internal/store/flowstore/explorer_budget.go",
        "MemoryBytes: 2 << 30",
        "MemoryBytes: 512 << 20",
        "TestInterfaceRoleExplanationEvaluatesCompleteSavedPolicyWithDefaultAdmission",
        "complete saved role policy cannot be explained under the default profile",
        "",
    ),
    "grant": (
        "internal/control/interface_role_explanation_api.go",
        "current.requestContext(ctx, actor)",
        "(&currentUserAuthority{principal: actor, policies: current.policies}).requestContext(ctx, actor)",
        "TestInterfaceRoleExplanationServesOwnedSourcesAndCurrentAuthority",
        "stale native principal retained revoked current grants",
        "",
    ),
    "publication": (
        "internal/control/interface_role_explanation_api.go",
        "if !sameInterfaceRoleInputs(before, after) {",
        "if false && !sameInterfaceRoleInputs(before, after) {",
        "TestInterfaceRoleExplanationRefusesMidComputationAuthorityChanges",
        "role explanation published after its authority changed",
        "source-anchor",
    ),
    "admission": (
        "internal/control/interface_role_associations.go",
        "budget *interfaceRoleBudget) (interfaceRolePeerAssociation, error) {",
        "budget *interfaceRoleBudget) (interfaceRolePeerAssociation, error) {\ncopyBudget := *budget; budget = &copyBudget",
        "TestInterfaceRolePeerAssociationSharesMultiPeerAdmission",
        "peer association reset shared operation admission",
        "",
    ),
    "publication-policy": (
        "internal/control/interface_role_explanation_api.go",
        "if !sameInterfaceRoleInputs(before, after) {",
        "if false && !sameInterfaceRoleInputs(before, after) {",
        "TestInterfaceRoleExplanationRefusesMidComputationAuthorityChanges",
        "role explanation published after its authority changed",
        "policy",
    ),
}


def current_role_explanation_controls():
    out = Path("artifacts/interface-prefix-transport").resolve()
    for name, (file, seam, replacement, root, marker, child) in EXPLANATION_CONTROLS.items():
        source = Path(file).resolve()
        original = source.read_text()
        assert original.count(seam) == 1
        mutant = overlay_source_path(out, "role_explanation_" + name + ".go")
        mutant.write_text(original.replace(seam, replacement))
        overlay = out / ("role_explanation_" + name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
        result = execute("internal/control", (root,), "role_explanation_" + name,
                         integration=True, overlay=overlay, child=child)
        if not report_regression_failed_on_assertion(result.stdout, result.returncode,
                package=PREFIX + "internal/control", root=root, child=child, marker=marker):
            raise RuntimeError("role explanation control did not fail its exact assertion: " + name)
    print(json.dumps({"current_role_explanation_controls": True}))


def interface_role_frozen_object_control():
    out = Path("artifacts/interface-prefix-transport")
    out.mkdir(parents=True, exist_ok=True)
    source = Path("internal/control/explorer_flow_snapshot_source.go").resolve()
    original = source.read_text()
    seam = "func (source *flowSnapshotSource) validateRoleAuthorization(ctx context.Context, scope flowsnapshot.Scope, receipt flowSnapshotValidity) error {"
    assert original.count(seam) == 1
    mutant = overlay_source_path(out, "role_frozen_current_authority_omitted.go")
    start = original.index(seam)
    end = original.index("func (source *flowSnapshotSource) validateTagAuthorization", start)
    mutant.write_text(original[:start] + seam + "\nreturn nil\n}\n\n" + original[end:])
    overlay = out / "role_frozen_current_authority_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant.resolve())}}))
    root = "TestInterfaceRoleFrozenObjectsKeepWholePagesCSVAndCurrentAuthority"
    result = execute("internal/control", (root,), "role_frozen_current_authority_omitted", integration=True, overlay=overlay)
    if not report_regression_failed_on_assertion(
            result.stdout, result.returncode, package=PREFIX + "internal/control", root=root, child="",
            marker="frozen role output survived changed current source authority"):
        raise RuntimeError("frozen role authority omission did not fail its exact assertion")


def interface_role_subject_control():
    out = Path("artifacts/interface-prefix-transport").resolve()
    source = Path("internal/tenantlife/subject.go").resolve()
    original = source.read_text()
    start = original.index('"interface_role_policies": {')
    end = original.index('"interface_role_overrides":', start)
    mutant = overlay_source_path(out, "role_policy_subject_omitted.go")
    mutant.write_text(original[:start] + '"interface_role_policies": {plane: "postgres:interface_role_policies", disposition: subjectTableNoSubject},\n' + original[end:])
    overlay = out / "role_policy_subject_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestInterfaceRoleSubjectKeepsWholeExportErasureAndTenantIsolation"
    result = execute("internal/tenantlife", (root,), "role_policy_subject_omitted", integration=True, overlay=overlay)
    if not report_regression_failed_on_assertion(result.stdout, result.returncode,
            package=PREFIX + "internal/tenantlife", root=root, child="",
            marker="role policy subject erasure retained owned text or deleted unrelated rows"):
        raise RuntimeError("role policy subject omission did not fail its exact assertion")


def standalone_role_source_control():
    out = Path("artifacts/interface-prefix-transport").resolve()
    source = Path("cmd/probectl-control/mcp_flow_sources.go").resolve()
    original = source.read_text()
    seam = "core.WithOpenDataStatus(en, nil, nil)"
    assert original.count(seam) == 1
    mutant = overlay_source_path(out, "standalone_role_source.go")
    mutant.write_text(original.replace(seam, "_ = en"))
    overlay = out / "standalone_role_source.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestMCPFlowSourcesRetainConfiguredLocalIXGeneration"
    result = execute("cmd/probectl-control", (root,), "standalone_role_source",
                     integration=True, overlay=overlay)
    if not report_regression_failed_on_assertion(result.stdout, result.returncode,
            package=PREFIX + "cmd/probectl-control", root=root, child="",
            marker="standalone role source omitted configured local IX prefixes"):
        raise RuntimeError("standalone source omission did not fail its exact assertion")
    print(json.dumps({"standalone_role_source_control": True}))


def current_role_source_controls():
    out = Path("artifacts/interface-prefix-transport").resolve()
    for name, file, seam, replacement, root, marker in (
        (
            "flow_owner_uniqueness_omitted", "tag_tenant_snapshot.go",
            "if _, exists := bindings[key]; exists || ambiguous[key] {",
            "if _, exists := bindings[key]; exists && false || ambiguous[key] && false {",
            "TestInterfaceRoleFlowBindingsKeepCurrentExplicitOriginsAndTenantScope",
            "unobserved competing collector manufactured unique role ownership",
        ),
        (
            "flow_origin_omitted", "interface_role_flow_bindings.go",
            "AND source.anchor_entity_id=node.id AND e.support_evidence_id IS NULL",
            "AND TRUE",
            "TestInterfaceRoleFlowBindingsKeepCurrentExplicitOriginsAndTenantScope",
            "inferred flow identity supplied explicit origin authority",
        ),
        (
            "flow_latest_omitted", "interface_role_flow_bindings.go",
            "(e.agent_id,e.configured_ref,e.alias_value,e.observed_at)",
            "(e.agent_id,e.configured_ref,e.alias_value,latest.observed)",
            "TestInterfaceRoleFlowBindingsKeepCurrentExplicitOriginsAndTenantScope",
            "expired latest flow identity revived an older source",
        ),
        (
            "prefix_latest_nonnull",
            "interface_role_snmp_inputs.go",
            "AND e.observed_at<=transaction_timestamp()",
            "AND e.snmp_interface_prefixes IS NOT NULL AND e.observed_at<=transaction_timestamp()",
            "TestInterfaceRoleInputsKeepCurrentOwnedSourcesAndNegativeFences",
            "latest unavailable prefix snapshot revived old metadata",
        ),
        (
            "poll_fault_withholding_omitted",
            "interface_role_snmp_inputs.go",
            "if err != nil || fault {",
            "if err != nil || (fault && input.IfIndex == 0) {",
            "TestInterfaceRoleInputsRequireAuthenticatedFaultClockAndRecovery",
            "current authenticated poll fault retained automatic source authority",
        ),
        (
            "peer_latest_asn_omitted",
            "interface_role_peer_inputs.go",
            "(e.agent_id,e.configured_ref,split_part(e.alias_value,'/as',1),e.observed_at)",
            "(e.agent_id,e.configured_ref,split_part(e.alias_value,'/as',1),latest.observed)",
            "TestInterfaceRoleInputsKeepCurrentOwnedSourcesAndNegativeFences",
            "new peer ASN retained a superseded relationship",
        ),
        (
            "peer_origin_anchor_omitted",
            "interface_role_peer_inputs.go",
            "AND source.anchor_entity_id=$3 AND e.support_evidence_id IS NULL",
            "AND TRUE",
            "TestInterfaceRoleInputsRequireExplicitBMPOriginRouterBinding",
            "inferred BMP peer identity supplied origin-router role authority",
        ),
    ):
        source = Path("internal/store", file).resolve()
        original = source.read_text()
        assert original.count(seam) == 1
        path = overlay_source_path(out, name + ".go")
        path.write_text(original.replace(seam, replacement))
        overlay = out / (name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
        result = execute(
            "internal/store", (root,), name, integration=True, overlay=overlay
        )
        if not report_regression_failed_on_assertion(
            result.stdout,
            result.returncode,
            package=PREFIX + "internal/store",
            root=root,
            child="",
            marker=marker,
        ):
            raise RuntimeError(
                f"omitted current source guard {name} did not fail its exact assertion"
            )
    print(json.dumps({"current_role_source_assertion_controls": True}))


def role_query_tenant_control():
    out = Path("artifacts/interface-prefix-transport").resolve()
    source = Path("internal/store/flowstore/explorer_roles.go").resolve()
    seam = "scope.TenantID != tenant"
    original = source.read_text()
    assert original.count(seam) == 1
    mutant = overlay_source_path(out, "role_query_tenant_omitted.go")
    mutant.write_text(original.replace(seam, "false"))
    overlay = out / "role_query_tenant_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestInterfaceRoleQueryProjectionRefusesAmbiguousExpiredOrPartialInputs"
    result = execute("internal/store/flowstore", (root,), "role_query_tenant_omitted", overlay=overlay)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/store/flowstore",
        root=root, child="foreign",
        marker="ambiguous, foreign or stale role projection was partially admitted",
    ):
        raise RuntimeError("role query tenant omission did not fail its exact foreign-row assertion")


def prefix_poll_refresh_control():
    source = Path("internal/device/entity_evidence.go").resolve()
    original = source.read_text()
    seam = "PrefixAttempted: inv.prefixAttempted, Prefixes: inv.interfacePrefixes"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    path = overlay_source_path(out, "prefix_poll_metadata_fingerprint_omitted.go")
    path.write_text(original.replace(seam, "PrefixAttempted: false, Prefixes: nil"))
    overlay = out / "prefix_poll_metadata_fingerprint_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
    root = "TestSNMPPollPrefixEvidenceKeepsCompleteEpochAndUnavailableFence"
    result = execute(
        "internal/device",
        (root,),
        "prefix_poll_metadata_fingerprint_omitted",
        overlay=overlay,
    )
    if not report_regression_failed_on_assertion(
        result.stdout,
        result.returncode,
        package=PREFIX + "internal/device",
        root=root,
        child="",
        marker="changed prefix availability retained the identity refresh epoch",
    ):
        raise RuntimeError(
            "omitted prefix fingerprint did not fail its current-prefix assertion"
        )
    print(json.dumps({"prefix_poll_current_epoch_control": True}))


def configuration_api_controls():
    source = Path("internal/control/interface_role_api.go").resolve()
    original = source.read_text()
    root = (
        "TestInterfaceRoleConfigurationAPIKeepsCompletePoliciesTenantCASAndAtomicAudit"
    )
    out = Path("artifacts/interface-prefix-transport").resolve()
    start = original.index(
        'return s.recordAudit(ctx, sc, r, "interface.role.policy.updated"'
    )
    end = original.index("\n\t\t})", start) + len("\n\t\t})")
    old_audit = original[start:end]
    for name, mutant, marker in (
        (
            "policy_body_old_quota",
            original.replace(
                "return min(b.ResponseBytes, b.MemoryBytes/16)",
                "return min(int64(1<<20), b.ResponseBytes, b.MemoryBytes/16)",
            ),
            "complete owned role policy was not published",
        ),
        (
            "policy_atomic_audit_omitted",
            original.replace(old_audit, "return nil"),
            "audit refusal did not fail the write",
        ),
    ):
        assert mutant != original
        path = overlay_source_path(out, name + ".go")
        path.write_text(mutant)
        overlay = out / (name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
        result = execute(
            "internal/control", (root,), name, integration=True, overlay=overlay
        )
        if not report_regression_failed_on_assertion(
            result.stdout,
            result.returncode,
            package=PREFIX + "internal/control",
            root=root,
            child="",
            marker=marker,
        ):
            raise RuntimeError(
                f"role API control {name} did not fail its exact assertion"
            )
    print(json.dumps({"role_configuration_api_controls": True}))


def ix_prefix_controls():
    out = Path("artifacts/interface-prefix-transport").resolve()
    for name, package, file, seam, replacement, root, marker in (
        ("ix_source_expiry", "internal/opendata", "peeringdb_prefixes.go",
         "out.Current = out.Enabled && p.availability(at) == nil", "out.Current = out.Enabled",
         "TestPeeringDBIXPrefixesKeepCompletePopulationClockAndOwnedMatches",
         "stale IX cache retained current evidence"),
        ("role_metadata_uuid", "internal/ai/mcp", "native_role_metadata.go",
         r'return []byte(strings.ReplaceAll(string(raw), "-", `\u002d`)), nil', "return raw, nil",
         "TestInterfaceRoleMCPMetadataKeepsExactGeneratedIDsAndFullTextRedaction",
         "native role redaction altered generated structural identity"),
        ("native_role_context", "internal/control", "mcp_native_flow_projection.go",
         "ctx = options[0].ctx", "ctx = context.Background()",
         "TestNativeFlowRoleProjectionHonorsCancellationAndExistingTenantScope",
         "canceled native role projection retained work"),
        ("native_role_projection", "internal/control", "mcp_native_flow_projection.go",
         "projectNativeFlowRoles(ctx, &out, source, tenant, budget)", "func() error { _ = budget; return nil }()",
         "TestNativeFlowRoleProjectionRetainsCompleteTenantProvenance",
         "native flow projection lost complete tenant role provenance"),
        ("native_role_identity", "internal/control", "mcp_native_flow_projection.go",
         "projectNativeFlowRoles(ctx, &out, source, tenant, budget)", "func() error { _ = budget; return nil }()",
         "TestNativeFlowRoleProjectionRefusesForeignMissingStaleOrChangedIdentity",
         "native role projection admitted foreign or inconsistent generation"),
        ("ix_owned_input", "internal/control", "interface_role_ix.go",
         "tenant.String() != scope.TenantID", "(tenant.String() != scope.TenantID && false)",
         "TestInterfaceRoleIXSourceMatchesOnlyOwnedCurrentInputsAndPreservesOverrides",
         "foreign tenant facts reached the shared IX cache"),
    ):
        source = Path(package, file).resolve()
        original = source.read_text()
        assert original.count(seam) == 1
        mutant = overlay_source_path(out, name + ".go")
        mutant.write_text(original.replace(seam, replacement))
        overlay = out / (name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
        children = ("11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") if name in ("ix_owned_input", "native_role_projection") else ("foreign_source",) if name == "native_role_identity" else ("",)
        for child in children:
            label = name + ("_" + child if child else "")
            test_package = "internal/control" if name == "role_metadata_uuid" else package
            result = execute(test_package, (root,), label, overlay=overlay, child=child)
            if not report_regression_failed_on_assertion(result.stdout, result.returncode,
                    package=PREFIX + test_package, root=root, child=child, marker=marker):
                raise RuntimeError("role source control did not fail its exact assertion: " + label)
    print(json.dumps({"ix_source_and_owned_input_controls": True}))


def bmp_routing_transport_controls():
    out = Path("artifacts/interface-prefix-transport").resolve()
    for name, file, seam, replacement, root, child, marker in (
        ("bmp_failed_cohort_identity_lost", "internal/bgp/bmp_routing_cohorts.go",
         "attempt.familyMask = previous.familyMask", "attempt.familyMask = 0",
         "TestBMPRoutingCohortsKeepOneSocketFamiliesSequencesAndWholeReplacement", "",
         "failed family record lost identity or closed a disjoint cohort"),
        ("bmp_disjoint_cohort_retirement_restored", "internal/bgp/bmp_routing_cohorts.go",
         "if mask != 0 && state.familyMask != 0 && mask&state.familyMask == 0 {",
         "if false && mask != 0 && state.familyMask != 0 && mask&state.familyMask == 0 {",
         "TestBMPRoutingCohortsKeepOneSocketFamiliesSequencesAndWholeReplacement", "",
         "one-socket disjoint family Peer Up replaced another cohort"),
        ("bmp_cohort_dispatch_ignored", "internal/bgp/bmp_routing_cohorts.go",
         "if mask != 0 && state.familyMask != 0 && mask&state.familyMask != mask {",
         "if false && mask != 0 && state.familyMask != 0 && mask&state.familyMask != mask {",
         "TestBMPRoutingCohortsKeepOneSocketFamiliesSequencesAndWholeReplacement", "",
         "family cohorts shared source generation or sequence"),
        ("bmp_message_family_bit_omitted", "internal/bgp/bmp_routing_family.go",
         "return 1 << (family - 1), nil", "return 1 << (family - family), nil",
         "TestRoutingMessageDispatchKeepsCompleteFamiliesAndNoInventedCompletion", "",
         "complete source message lost family dispatch or invented completion"),
        ("loc_rib_explicit_family_cohort_omitted", "internal/bgp/peer_up.go",
         'if peer.Header.View == BMPLocRIB && peer.SourceProfile.Format == "" && len(capabilities.mpFamilies) != 0 {',
         'if false && peer.Header.View == BMPLocRIB && peer.SourceProfile.Format == "" && len(capabilities.mpFamilies) != 0 {',
         "TestLocRIBPeerUpKeepsExplicitFamilyCohortsAndAdjacentDefaults", "",
         "Loc-RIB Peer Up invented another emulated family cohort"),
        ("frr_explicit_serializer_omitted", "internal/bgp/route_add_path.go",
         "if format == RoutingSourceFRRLocRIBV1 {", "if false && format == RoutingSourceFRRLocRIBV1 {",
         "TestFRRRoutingProfileKeepsOriginalMetadataFamiliesAndStrictDefault", "",
         "explicit FRR source profile refused complete original metadata or lost declared families"),
        ("frr_unknown_profile_accepted", "internal/bgp/routing_source_profile.go",
         "profile.Format != RoutingSourceFRRLocRIBV1 ||", "false ||",
         "TestFRRRoutingProfileRefusesUnknownAmbiguousAndUnadmittedSources", "",
         "invalid source profile exposed partial routing metadata"),
        ("bmp_selector_identifier_omitted", "internal/bgp/bmp_routing_book.go",
         "identifier: header.BGPIdentifier.As4()", "identifier: [4]byte{}",
         "TestBMPRoutingSelectorsKeepIndependentGenerationsRefusalsAndSourceClosure", "",
         "routing selectors shared a generation or sequence"),
        ("bmp_selector_distinguisher_omitted", "internal/bgp/bmp_routing_book.go",
         "distinguisher: header.Distinguisher", "distinguisher: [8]byte{}",
         "TestBMPRoutingMetadataAdmissionKeepsWholePopulationAndReclaimsSourceState", "",
         "complete selector population clipped to a former count or lost metadata accounting"),
        ("bmp_stream_byte_admission_omitted", "internal/bgp/bmp_routing_book.go",
         "if nextBytes > streams.limit || streams.used-oldBytes > streams.limit-nextBytes {", "if false {",
         "TestBMPRoutingMetadataAdmissionKeepsWholePopulationAndReclaimsSourceState", "",
         "unadmitted selector staged partial state or changed known routing population"),
        ("bmp_source_closure_lost_selector", "internal/bgp/bmp_routing_stream.go",
         "states.remove(peer)\n\t\t}\n\t\treturn\n\t}\n\tif peer.routingPeerUp",
         "states.remove(peer)\n\t\t\tbreak\n\t\t}\n\t\treturn\n\t}\n\tif peer.routingPeerUp",
         "TestBMPRoutingSelectorsKeepIndependentGenerationsRefusalsAndSourceClosure", "",
         "source closure left known routing selectors current"),
        ("bmp_loss_lost_selector", "internal/bgp/bmp_routing_stream.go",
         "states.put(peer, state)\n\t\t}\n\t}\n}\n\n// Reset",
         "states.put(peer, state)\n\t\t\tbreak\n\t\t}\n\t}\n}\n\n// Reset",
         "TestBMPRoutingSourceLossRetiresAllSelectorsAfterSocketDeregistration", "",
         "physical loss left known routing selectors current"),
        ("bmp_reset_acknowledgement_omitted", "internal/agent/bgp_routing_message.go",
         "if raw.SourceReset {", "if false && raw.SourceReset {",
         "TestRoutingResetClientRequiresExactInvalidationReceipt", "",
         "confirmed source reset was reported as unavailable"),
        ("bmp_adapter_stage_hidden", "cmd/probectl-bmp-listener/main.go",
         "func (o observedBMPEvidence) StageRoutingPeer(",
         "func (o observedBMPEvidence) hiddenStageRoutingPeer(",
         "TestBMPEvidenceAdapterKeepsCompleteRoutingTransport", "",
         "shipped metrics adapter hides routing staging transport"),
        ("bmp_adapter_stream_hidden", "cmd/probectl-bmp-listener/main.go",
         "func (o observedBMPEvidence) SubmitRoutingMessage(",
         "func (o observedBMPEvidence) hiddenSubmitRoutingMessage(",
         "TestBMPEvidenceAdapterKeepsCompleteRoutingTransport", "",
         "shipped metrics adapter hides routing message transport"),
        ("bmp_raw_session_cancelled", "internal/bgp/bmp_routing_stream.go",
         "reset := func(generation string, sequence *int64) {",
         "l.cancelRoutingSession(peer.sessionHandle)\n\treset := func(generation string, sequence *int64) {",
         "TestBMPRoutingEvidenceFailureKeepsRawSessionAndRetiresOnlyOwnedGenerations", "message",
         "routing evidence failure canceled raw BGP collection"),
        ("bmp_queue_loss_ignored", "internal/bgp/bmp_routing_stream.go",
         "l.loseRoutingEvidence(session)", "_ = session",
         "TestBMPRoutingQueueLossKeepsRawSessionAndInvalidatesBeforePendingData", "",
         "lost routing frame allowed queued data to retain a current generation"),
        ("bmp_idle_loss_ignored", "internal/bgp/bmp_entity_evidence.go",
         "l.retireLostRoutingStreams(ctx, routing)", "_ = routing",
         "TestBMPRoutingLossWakesIdleEvidenceWorkerWithoutClosingRawSource", "",
         "idle evidence worker kept current routing authority after local loss"),
    ):
        source = Path(file).resolve()
        original = source.read_text()
        assert original.count(seam) == 1
        mutant = overlay_source_path(out, name + ".go")
        mutant.write_text(original.replace(seam, replacement))
        overlay = out / (name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
        package = str(Path(file).parent)
        result = execute(package, (root,), name, overlay=overlay, child=child)
        if not report_regression_failed_on_assertion(
            result.stdout, result.returncode, package=PREFIX + package, root=root,
            child=child, marker=marker,
        ):
            raise RuntimeError(name + " did not fail its exact assertion")


def peering_interval_combination_control():
    source = Path("internal/flow/peering_estimate.go").resolve()
    original = source.read_text()
    seam = "values[i].Add(values[i], fact.bytes)"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    mutant = overlay_source_path(out, "peering_interval_combination_omitted.go")
    mutant.write_text(original.replace(seam, "values[i].Set(fact.bytes)"))
    overlay = out / "peering_interval_combination_omitted.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
    root = "TestPeeringEstimateCombinesIntervalsBeforeExactPercentile"
    result = execute("internal/flow", (root,), "peering_interval_combination_omitted", overlay=overlay)
    if not report_regression_failed_on_assertion(
        result.stdout, result.returncode, package=PREFIX + "internal/flow", root=root,
        child="", marker="combined-interval hand p95 differs from eighteen 2s and two 101s",
    ):
        raise RuntimeError("peering interval combination did not fail its exact hand assertion")


def peering_flow_clock_control():
    source = Path("internal/store/flowstore/peering_traffic_clickhouse.go").resolve()
    original = source.read_text()
    out = Path("artifacts/interface-prefix-transport").resolve()
    root = "TestPeeringTrafficRealStoreKeepsWholeTenantStatesDirectionsAndOriginalClock"
    for name, seam, replacement, marker in (
        ("peering_flow_original_clock_omitted", " AND peer_capture.peer_clock=routing_captured_unix_nanos", "",
         "actual peering join replaced an original capture clock"),
        ("peering_flow_owner_population_collapsed", " ALL INNER JOIN (SELECT DISTINCT peer_tenant,peer_exporter,peer_protocol,peer_domain", " ANY INNER JOIN (SELECT DISTINCT peer_tenant,peer_exporter,peer_protocol,peer_domain",
         "actual peering query lost complete owned tenant states, directions, counters or partial intervals"),
    ):
        assert original.count(seam) == 1
        mutant = overlay_source_path(out, name + ".go")
        mutant.write_text(original.replace(seam, replacement))
        overlay = out / (name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
        result = execute("internal/store/flowstore", (root,), name, integration=True, overlay=overlay)
        if not report_regression_failed_on_assertion(result.stdout, result.returncode, package=PREFIX + "internal/store/flowstore", root=root, child="", marker=marker):
            raise RuntimeError(name + " did not fail its exact assertion")


def main(integration, flow_integration=False):
    if not integration:
        artifact_selftest()
    selected = FLOW_INTEGRATION if flow_integration else INTEGRATION if integration else UNIT
    positive_failures = []
    for package, roots in selected.items():
        result = execute(
            package, roots, package.replace("/", "_") + "_positive", integration
        )
        failures = classify(
            result.stdout, result.returncode, package=PREFIX + package, tests=roots
        )
        if failures:
            positive_failures.extend(failures)
            print(json.dumps({"required_positive_failure": package, "errors": failures}))
    if flow_integration:
        peering_flow_clock_control()
    if integration and not flow_integration:
        bgp_source_peer_control()
        bgp_source_origin_control()
        bgp_peer_session_control()
        bgp_routing_extended_control()
        bgp_routing_authority_control()
        bgp_routing_generation_control()
        bgp_routing_write_controls()
        current_role_explanation_controls()
        standalone_role_source_control()
        interface_role_subject_control()
        interface_role_frozen_object_control()
        current_role_source_controls()
        configuration_incarnation_controls()
        configuration_api_controls()
        configuration_silo_lock_control()
    if not integration:
        bmp_routing_transport_controls()
        peering_interval_combination_control()
        snmp_dual_stack_address_control()
        role_query_tenant_control()
        prefix_poll_refresh_control()
        configuration_regexp_expansion_control()
        configuration_native_request_control()
        configuration_raw_cli_body_control()
        configuration_missing_source_control()
        ix_prefix_controls()
        source = Path("internal/agent/entity_client.go")
        original = source.read_text()
        seam = "if proto.Size(request) > 1<<20 {"
        assert original.count(seam) == 1
        try:
            source.write_text(
                original.replace(seam, "if false && proto.Size(request) > 1<<20 {")
            )
            result = execute("internal/agent", (ROOT,), "whole_request_guard_omitted")
        finally:
            source.write_text(original)
        if not report_regression_failed_on_assertion(
            result.stdout,
            result.returncode,
            package=PREFIX + "internal/agent",
            root=ROOT,
            marker=MARKER,
            child="",
        ):
            raise RuntimeError(
                "omitted whole-request guard did not fail its exact complete-batch assertion"
            )
    if positive_failures:
        raise RuntimeError(f"required prefix transport proof missing/failed: {positive_failures}")
    print(
        json.dumps(
            {
                "kind": "real-integration" if integration else "simulation",
                "scope": "ClickHouse complete raw/rollup with modeled role projections"
                if flow_integration
                else "mTLS/Postgres with simulated SNMP inputs"
                if integration
                else "typed complete-set/native wire and silo plan",
                "passed": True,
                "real_router_acceptance": "owed",
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--artifact-selftest", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--integration", action="store_true")
    mode.add_argument("--flow-integration", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
    elif args.artifact_selftest:
        artifact_selftest()
    else:
        main(args.integration or args.flow_integration, args.flow_integration)
