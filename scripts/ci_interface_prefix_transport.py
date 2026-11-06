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
    "internal/opendata": (
        "TestPeeringDBIXPrefixesKeepCompletePopulationClockAndOwnedMatches",
        "TestPeeringDBIXPrefixesRefusePartialAmbiguousOrMalformedSnapshot",
        "TestPeeringDBIXPrefixesKeepInactiveAndExpiredSourcesVisibleWithoutMemberships",
    ),
    "internal/config": (
        "TestFlowIXPrefixLocalConfigKeepsNoEgressAndPositiveFreshness",
    ),
    "internal/store/flowstore": (
        "TestInterfaceRoleQueryProjectionKeepsTenantIdentityAndCompleteMetadata",
        "TestInterfaceRoleQueryProjectionRefusesAmbiguousExpiredOrPartialInputs",
        "TestInterfaceRoleExplorerPreservesBothDirectionsMissingRowsAndTenantBoundary",
        "TestInterfaceRoleExplorerSQLKeepsFixedTenantJoinAndCompleteExternalValues",
    ),
    "internal/flow": (
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
        "TestInterfaceRoleNativeToolsPreserveCompleteInputAndUserTenantBoundary",
        "TestInterfaceRoleNativeExplanationRequiresEverySourceBeforeBackend",
    ),
    "internal/cli": (
        "TestInterfaceRoleCLIUsesOwnedRoutesAndExactDecimalRevision",
        "TestInterfaceRoleCompletePolicyReachesNamedRawCLIAndGeneratedSDK",
    ),
    "internal/control": (
        "TestNativeFlowRoleProjectionHonorsCancellationAndExistingTenantScope",
        "TestNativeFlowRoleProjectionRetainsCompleteTenantProvenance",
        "TestNativeFlowRoleProjectionRefusesForeignMissingStaleOrChangedIdentity",
        "TestInterfaceRoleMCPMetadataKeepsExactGeneratedIDsAndFullTextRedaction",
        "TestInterfaceRoleMCPMetadataRefusesMalformedIdentifiersAndRevisions",
        "TestInterfaceRoleIXSourceMatchesOnlyOwnedCurrentInputsAndPreservesOverrides",
        "TestBuildEnrichmentIXPrefixFailureRemainsVisibleAndMakesNoOutboundSource",
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
    "internal/entity": (
        "TestSNMPPrefixSnapshotKeepsCompleteOwnedCanonicalRows",
        "TestSNMPPrefixSnapshotRejectsPartialMalformedAndForeignClaims",
        "TestSNMPPrefixSnapshotAdmissionNeverTruncatesToFit",
        "TestInterfaceRolePolicyCompleteReachKeepsOrderAndOwnedCopies",
        "TestInterfaceRolePolicyRefusesAmbiguityAndKeepsCanonicalSets",
    ),
    "internal/agent": (
        "TestRoutingMessageClientKeepsExactStreamAndRefusesMixedReceipts",
        "TestRoutingStageClientPreservesCompleteRequestAndRequiresPrivateReceipt",
        "TestSNMPPrefixEvidenceWireKeepsCompleteSetAndWholeRequestAdmission",
    ),
    "internal/agenttransport": (
        "TestRoutingProjectionKeepsWholePopulationAndAdmitsDescriptorExpansion",
        "TestSNMPPrefixReceiverKeepsPresenceAndRefusesPartialTables",
    ),
    "internal/bgp": (
        "TestRoutingLifecycleRequiresCompleteMatchingSourceFrame",
        "TestBMPRoutingWholeStreamKeepsFIFOAndResetsOnSourceClosure",
        "TestBMPRoutingStagingUsesAdmittedIdentityAndCompleteOriginalPeerUp",
        "TestRoutingPeerUpKeepsCompleteDeclaredFamiliesAndRefusesMalformedSource",
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
        "TestInterfaceRoleCASUsesExactIdentityAndDecimalRevision",
        "TestBGPRoutingAuthorityRequiresTenantAndCompleteSourceBeforeStorage",
        "TestBGPRoutingLookupRequiresTenantExactViewAndWholeAdmissionBeforeStorage",
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
        "TestEntityRegistryForeignKeysFollowAllSiloCopies",
        "TestInterfaceRoleStoragePlanKeepsLocalKindAndTenantForeignKeys",
        "TestBGPRoutingPlanKeepsEveryReferenceInItsTenantSchema",
    ),
}
FLOW_INTEGRATION = {
    "internal/store/flowstore": (
        "TestInterfaceRoleExplorerClickHouseKeepsTenantDirectionsAndCompleteTotals",
    ),
}
INTEGRATION = {
    "internal/bgp": ("TestBMPLocRIBRealRouterKeepsCompletePeerAndFamilyMarkers",),
    "cmd/probectl-control": ("TestMCPFlowSourcesRetainConfiguredLocalIXGeneration",),
    "ee/silo": (
        "TestInterfaceRoleAPIKeepsSiloRelationsLockedBeforeConfigurationSQL",
        "TestInterfaceRoleInputsFollowManagedAndHybridCurrentAuthority",
    ),
    "internal/control": (
        "TestNativeFlowRoleTLSKeepsWholeProvenanceAndCurrentAuthority",
        "TestInterfaceRoleNativeTLSKeepsTenantConfigurationAndCurrentSources",
        "TestInterfaceRoleStdioKeepsWholePoliciesAndRechecksCredentialWithinStream",
        "TestFlowRoleQueryKeepsCurrentOwnedSourcesAndRefusesPublicationChanges",
        "TestInterfaceRoleFrozenObjectsKeepWholePagesCSVAndCurrentAuthority",
        "TestInterfaceRoleConfigurationAPIKeepsCompletePoliciesTenantCASAndAtomicAudit",
        "TestInterfaceRoleExplanationServesOwnedSourcesAndCurrentAuthority",
        "TestInterfaceRoleExplanationRefusesMidComputationAuthorityChanges",
        "TestInterfaceRoleExplanationEvaluatesCompleteSavedPolicyWithDefaultAdmission",
    ),
    "internal/store": (
        "TestBGPRoutingStagingKeepsTenantRetryLeaseAndAtomicCompletePeer",
        "TestBGPRoutingWholeStreamKeepsFamilyAtomicityReplayAndTenantFence",
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
        "TestRoutingStagingRealMTLSKeepsTenantOriginRetryAndPrivateState",
        "TestSNMPPrefixRealMTLSKeepsTenantSenderReplayAndCompleteMetadata",
    ),
    "internal/tenantlife": (
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
    args = ["go", "test", "-race", "-count=1", "-timeout=5m", "-json"]
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
        timeout=360,
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
        "AND view_kind='loc_rib' AND NOT filtered",
        "AND NOT filtered",
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
        package = str(Path(file).parent)
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
    seam = "op.ExactJSON, op.MaxBodyBytes = profile.ExactJSON, profile.MaxBodyBytes"
    assert original.count(seam) == 1
    out = Path("artifacts/interface-prefix-transport").resolve()
    path = overlay_source_path(out, "raw_cli_policy_old_quota.go")
    path.write_text(original.replace(seam, "op.ExactJSON = profile.ExactJSON"))
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
