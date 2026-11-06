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
        "TestSNMPPrefixEvidenceWireKeepsCompleteSetAndWholeRequestAdmission",
    ),
    "internal/agenttransport": (
        "TestSNMPPrefixReceiverKeepsPresenceAndRefusesPartialTables",
    ),
    "internal/store": (
        "TestInterfaceRoleCASUsesExactIdentityAndDecimalRevision",
        "TestInterfaceRoleStorageRequiresTenantBeforeAnyQuery",
        "TestInterfaceRoleInputsRequireTenantBeforeStorageAndCanonicalPeerValues",
        "TestInterfaceRoleFlowBindingRequiresTenantBeforeStorageAndExactIdentity",
    ),
    "ee/silo": (
        "TestEntityRegistryForeignKeysFollowAllSiloCopies",
        "TestInterfaceRoleStoragePlanKeepsLocalKindAndTenantForeignKeys",
    ),
}
FLOW_INTEGRATION = {
    "internal/store/flowstore": (
        "TestInterfaceRoleExplorerClickHouseKeepsTenantDirectionsAndCompleteTotals",
    ),
}
INTEGRATION = {
    "ee/silo": ("TestInterfaceRoleAPIKeepsSiloRelationsLockedBeforeConfigurationSQL",),
    "internal/control": (
        "TestFlowRoleQueryKeepsCurrentOwnedSourcesAndRefusesPublicationChanges",
        "TestInterfaceRoleConfigurationAPIKeepsCompletePoliciesTenantCASAndAtomicAudit",
        "TestInterfaceRoleExplanationServesOwnedSourcesAndCurrentAuthority",
        "TestInterfaceRoleExplanationRefusesMidComputationAuthorityChanges",
        "TestInterfaceRoleExplanationEvaluatesCompleteSavedPolicyWithDefaultAdmission",
    ),
    "internal/store": (
        "TestInterfaceRoleInputsKeepCurrentOwnedSourcesAndNegativeFences",
        "TestInterfaceRoleInputsRetainWholePrefixTableAndRefusePartialBudget",
        "TestInterfaceRoleInputsRequireAuthenticatedFaultClockAndRecovery",
        "TestInterfaceRoleInputsRequireExplicitBMPOriginRouterBinding",
        "TestInterfaceRoleFlowBindingsKeepCurrentExplicitOriginsAndTenantScope",
        "TestEntityRegistryTenantAndContextIsolation",
        "TestSNMPPrefixStorageKeepsCompleteWirePopulationAndRepairsManagedCopies",
        "TestDashboardReportTenantIsolation",
        "TestInterfaceRoleConfigurationPostgresKeepsTenantCASAndOverrideIncarnations",
    ),
    "internal/agenttransport": (
        "TestSNMPPrefixRealMTLSKeepsTenantSenderReplayAndCompleteMetadata",
    ),
    "internal/tenantlife": (
        "TestEntityEvidenceSubjectMetadataExportErasureAndIsolation",
    ),
}
ROOT = UNIT["internal/agent"][0]
MARKER = "combined complete prefix request escaped whole-wire admission"


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
        path = out / (name + "_incarnation_omitted.go")
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
    path = out / "raw_cli_policy_old_quota.go"
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
    path = out / "manual_override_old_source_requirement.go"
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
    path = out / "native_request_old_quota.go"
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
    path = out / "role_silo_relation_locks_omitted.go"
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
    path = out / "role_regexp_expansion_admission_omitted.go"
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
        mutant = out / ("role_explanation_" + name + ".go")
        mutant.write_text(original.replace(seam, replacement))
        overlay = out / ("role_explanation_" + name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(source): str(mutant)}}))
        result = execute("internal/control", (root,), "role_explanation_" + name,
                         integration=True, overlay=overlay, child=child)
        if not report_regression_failed_on_assertion(result.stdout, result.returncode,
                package=PREFIX + "internal/control", root=root, child=child, marker=marker):
            raise RuntimeError("role explanation control did not fail its exact assertion: " + name)
    print(json.dumps({"current_role_explanation_controls": True}))


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
        path = out / (name + ".go")
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
    mutant = out / "role_query_tenant_omitted.go"
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
    path = out / "prefix_poll_metadata_fingerprint_omitted.go"
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
        path = out / (name + ".go")
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


def main(integration, flow_integration=False):
    selected = FLOW_INTEGRATION if flow_integration else INTEGRATION if integration else UNIT
    for package, roots in selected.items():
        result = execute(
            package, roots, package.replace("/", "_") + "_positive", integration
        )
        failures = classify(
            result.stdout, result.returncode, package=PREFIX + package, tests=roots
        )
        if failures:
            raise RuntimeError(
                f"required prefix transport proof missing/failed: {failures}"
            )
    if integration and not flow_integration:
        current_role_explanation_controls()
        current_role_source_controls()
        configuration_incarnation_controls()
        configuration_api_controls()
        configuration_silo_lock_control()
    if not integration:
        role_query_tenant_control()
        prefix_poll_refresh_control()
        configuration_regexp_expansion_control()
        configuration_native_request_control()
        configuration_raw_cli_body_control()
        configuration_missing_source_control()
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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--integration", action="store_true")
    mode.add_argument("--flow-integration", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
    else:
        main(args.integration or args.flow_integration, args.flow_integration)
