// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type complianceControlCapture struct {
	from, checked time.Time
	packageID     string
	sourceDigest  string
	captureDigest string
}

func cleanComplianceControlReportDefinition(d *dashboardDefinition) error {
	if d.ComplianceControl == "" {
		if d.ComplianceFlow != nil {
			return apierror.Validation("compliance_flow requires an explicit flow-backed control")
		}
		return nil
	}
	kind := compliance.ControlEvidenceSection(d.ComplianceControl)
	if kind == "" {
		return apierror.Validation("compliance_control requires a supported network evidence control reference")
	}
	if d.CarrierClaim != nil || d.ClientReport != nil || len(d.FlowSources) != 0 || !d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.IsZero() || len(d.Metrics) != 0 {
		return apierror.Validation("compliance_control derives its observation interval and source. Omit other report sources, bounds and metrics.")
	}
	if kind == compliance.SectionAuditChain {
		if d.ComplianceFlow != nil {
			return apierror.Validation("the audit control uses the retained tenant audit stream")
		}
		return nil
	}
	if _, _, err := parseComplianceFlowDefinition(kind, d.ComplianceFlow); err != nil {
		return err
	}
	// Keep the stored/read wire shape valid when a typed create omits metrics.
	d.Metrics = map[string]string{}
	return nil
}

func parseComplianceFlowDefinition(kind string, definition *reporting.ComplianceFlowDefinition) (time.Duration, []store.IncidentImpactEntity, error) {
	if definition == nil {
		return 0, nil, apierror.Validation("select canonical device or interface sources within the report definition budget")
	}
	lookback, err := time.ParseDuration(definition.Lookback)
	if err != nil || lookback < time.Second || lookback%time.Microsecond != 0 {
		return 0, nil, apierror.Validation("compliance_flow requires a lookback of at least one second in whole microseconds, such as 24h")
	}
	if kind == compliance.SectionSegmentation {
		if len(definition.Policy) > maxDashboardManifestBytes {
			return 0, nil, apierror.Validation("the segmentation policy exceeds the report definition budget")
		}
		if _, err := compliance.ParsePolicy([]byte(definition.Policy)); err != nil {
			return 0, nil, apierror.Validation("the selected segmentation policy is invalid")
		}
	} else if definition.Policy != "" {
		return 0, nil, apierror.Validation("monitoring coverage uses the selected original flow sources and interval")
	}
	members, err := complianceFlowMembers(definition.Sources)
	return lookback, members, err
}

func complianceFlowMembers(sources []reporting.ComplianceFlowSource) ([]store.IncidentImpactEntity, error) {
	if len(sources) == 0 || len(sources) > maxDashboardManifestBytes/64 {
		return nil, apierror.Validation("select canonical device or interface sources within the report definition budget")
	}
	members := make([]store.IncidentImpactEntity, 0, len(sources))
	seen := make(map[reporting.ComplianceFlowSource]bool, len(sources))
	for _, source := range sources {
		if !reportRequirementUUID(source.ContextID) || !reportRequirementUUID(source.EntityID) || seen[source] {
			return nil, apierror.Validation("flow evidence sources require distinct canonical context and entity IDs")
		}
		seen[source] = true
		members = append(members, store.IncidentImpactEntity{ContextID: source.ContextID, EntityID: source.EntityID})
	}
	return members, nil
}

func (s *Server) authorizeComplianceControlScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, control string) error {
	if control != compliance.CMMCAuditControl || actor == nil || actor.TenantID != sc.Tenant.String() || actor.UserID == "" {
		return apierror.Forbidden("current compliance report source scope is unavailable")
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	return s.authorize(ctx, principal, permAuditRead, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID})
}

func (s *Server) captureComplianceControlReport(ctx context.Context, actor *auth.Principal, definition dashboardDefinition, budget flowstore.ExplorerBudget) (_ *reportFlowCapture, captureErr error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || actor.TenantID != bound.String() {
		return nil, apierror.Forbidden("compliance report source tenant is unavailable")
	}
	if s.pool == nil || s.fairnessGate == nil || len(s.evidenceSigningKey) == 0 || budget.Validate() != nil {
		return nil, apierror.Unavailable("compliance report verification, admission or signing is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return nil, tagQueryAdmissionError(err)
	}
	var signed *reporting.BodyStage
	closeCapture := func() {
		if signed != nil {
			_ = signed.Close()
		}
		release()
	}
	defer func() {
		if captureErr != nil {
			closeCapture()
		}
	}()
	evidence, capture, err := s.collectComplianceControlEvidence(ctx, actor, definition, budget)
	if err != nil {
		return nil, err
	}
	manifest, attachments, err := compliance.BuildControlEvidence(evidence)
	if err != nil {
		return nil, err
	}
	capture.controlCapture.packageID = manifest.BundleID
	from, to := capture.controlCapture.from, capture.controlCapture.checked
	raw, err := compliance.SignAuditorBundle(manifest, attachments, s.evidenceSigningKey)
	if err != nil {
		return nil, err
	}
	limits := reporting.BodyStageLimitsForBytes(int64(len(raw)))
	if limits.MemoryBytes > budget.MemoryBytes/8 {
		return nil, store.ErrClientReportBudget
	}
	signed, _, err = reporting.StageBody(ctx, actor.TenantID, limits, func(w io.Writer) error {
		_, err := w.Write(raw)
		return err
	})
	if err != nil {
		return nil, err
	}
	summary := sealedClientReportTable(actor.TenantID, "compliance-control-summary", "Control evidence result", from, to,
		plainClientReportColumns([]string{"framework", "guide_version", "standard_version", "control", "checked_at", "source_status", "reason", "signed_package_id"}),
		[][]string{{manifest.Control.Framework, manifest.Control.GuideVersion, manifest.Control.StandardVersion, definition.ComplianceControl,
			evidence.CollectedAt.Format(time.RFC3339Nano), evidence.Evidence.Status, evidence.Evidence.Reason, manifest.BundleID}})
	summary.Source = complianceControlReportCoverage(capture)
	encoded, err := signedReportEvidenceTable(ctx, signed, manifest.BundleID, "compliance-control-"+manifest.BundleID+".json", reporting.CSVTable{
		ID: "compliance-control-evidence", Title: "Complete signed control evidence", TenantID: actor.TenantID,
		Source:       "CSV: concatenate decoded signed_package_base64_chunk cells in ordinal order. PDF: extract the attached JSON. Use verify-bundle --expected-fingerprint with the operator's independently trusted fingerprint.",
		AbsoluteFrom: from, AbsoluteTo: to,
	})
	if err != nil {
		return nil, err
	}
	capture.Tables = []reporting.CSVTable{summary, encoded}
	capture.release = closeCapture
	return capture, nil
}

func complianceControlReportDocument(view *store.DashboardView, definition dashboardDefinition, tenantName, generator string, at time.Time, capture *reportFlowCapture) (reporting.Document, error) {
	current := capture.controlCapture
	if current == nil || capture.ComplianceControl != definition.ComplianceControl {
		return reporting.Document{}, errReportSourceRequirements
	}
	return reporting.Document{Title: view.Name, Preset: view.Preset, TenantName: tenantName, TenantScope: view.TenantID,
		AbsoluteFrom: current.from, AbsoluteTo: current.checked, GeneratedAt: at, GeneratedBy: generator,
		Provenance:     append(append([]string{}, definition.Provenance...), "Offline signed control evidence "+current.packageID),
		RedactionState: definition.RedactionState,
		CoverageLimitations: append(append([]string{}, definition.CoverageLimitations...),
			complianceControlReportCoverage(capture), "The assessor uses this evidence alongside the required assessments."),
		Tables: capture.Tables}, nil
}

func complianceControlReportCoverage(capture *reportFlowCapture) string {
	if capture.ComplianceFlow != nil {
		return "Coverage reflects authenticated original flows from the selected measurement points during the observation interval."
	}
	return "The scan checks the retained probectl tenant audit stream at collection time."
}

func (s *Server) collectComplianceControlEvidence(ctx context.Context, actor *auth.Principal, definition dashboardDefinition, budget flowstore.ExplorerBudget) (compliance.ControlEvidenceInput, *reportFlowCapture, error) {
	control := definition.ComplianceControl
	evidence := compliance.ControlEvidenceInput{TenantID: actor.TenantID, Reference: control, Deployment: s.auditorDeploymentIdentity()}
	capture := &reportFlowCapture{TenantID: actor.TenantID, ComplianceControl: control, controlCapture: &complianceControlCapture{}}
	if control != compliance.CMMCAuditControl {
		if err := s.collectComplianceFlowControl(ctx, actor, definition, budget, &evidence, capture); err != nil {
			return evidence, nil, err
		}
		return evidence, capture, nil
	}
	capture.controlCapture.from = time.Now().UTC()
	var coverage audit.TenantVerificationCoverage
	var verificationErr error
	if err := tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := s.authorizeComplianceControlScope(ctx, sc, actor, control); err != nil {
			return err
		}
		coverage, verificationErr = audit.TenantVerifyWithCoverage(ctx, sc)
		return nil
	}); err != nil {
		return evidence, nil, err
	}
	evidence.CollectedAt = time.Now().UTC()
	capture.controlCapture.checked = evidence.CollectedAt
	evidence.Evidence = auditorAuditChainEvidence(coverage, verificationErr, evidence.CollectedAt)
	return evidence, capture, nil
}

func (s *Server) collectComplianceFlowControl(ctx context.Context, actor *auth.Principal, definition dashboardDefinition, budget flowstore.ExplorerBudget, evidence *compliance.ControlEvidenceInput, capture *reportFlowCapture) error {
	lookback, members, err := parseComplianceFlowDefinition(compliance.ControlEvidenceSection(definition.ComplianceControl), definition.ComplianceFlow)
	if err != nil {
		return err
	}
	if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := s.authorizeDashboardFlowPoints(ctx, sc, actor, definition); err != nil {
			return err
		}
		var err error
		capture.SourceGeneration, err = flowsnapshot.SourceGenerationInScope(ctx, sc)
		return err
	}); err != nil {
		return err
	}
	// PostgreSQL persists artifact bounds at microsecond precision. Use the
	// same endpoints in the raw query, signed package and artifact metadata.
	to := time.Now().UTC().Truncate(time.Microsecond)
	from := to.Add(-lookback)
	window, err := s.readComplianceFlowWindow(ctx, actor, members, from, to, budget)
	if err != nil {
		return err
	}
	evidence.Evidence, err = projectComplianceFlowControl(ctx, actor.TenantID, definition.ComplianceControl, definition.ComplianceFlow.Policy, window)
	if err != nil {
		return err
	}
	evidence.CollectedAt = time.Now().UTC()
	evidence.Window = &compliance.ControlEvidenceWindow{From: from, To: to}
	capture.controlCapture.from, capture.controlCapture.checked = from, to
	capture.controlCapture.sourceDigest, capture.controlCapture.captureDigest = window.sourceDigest, window.publicationDigest
	capture.ComplianceFlow = &complianceFlowRequirements{Sources: definition.ComplianceFlow.Sources, Originals: window.originals}
	return nil
}
