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
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type complianceControlCapture struct {
	from, checked time.Time
	packageID     string
}

func cleanComplianceControlReportDefinition(d *dashboardDefinition) error {
	if d.ComplianceControl == "" {
		return nil
	}
	if d.ComplianceControl != compliance.CMMCAuditControl {
		return apierror.Validation("compliance_control requires a supported network evidence control reference")
	}
	if d.CarrierClaim != nil || d.ClientReport != nil || len(d.FlowSources) != 0 || !d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.IsZero() || len(d.Metrics) != 0 {
		return apierror.Validation("compliance_control derives the audit verification interval and source. Omit other report sources, bounds and metrics.")
	}
	return nil
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

func (s *Server) captureComplianceControlReport(ctx context.Context, actor *auth.Principal, control string, budget flowstore.ExplorerBudget) (_ *reportFlowCapture, captureErr error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || actor.TenantID != bound.String() {
		return nil, apierror.Forbidden("compliance report source tenant is unavailable")
	}
	if s.pool == nil || s.fairnessGate == nil || len(s.evidenceSigningKey) == 0 {
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
	from := time.Now().UTC()
	var coverage audit.TenantVerificationCoverage
	var verificationErr error
	if err := tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := s.authorizeComplianceControlScope(ctx, sc, actor, control); err != nil {
			return err
		}
		coverage, verificationErr = audit.TenantVerifyWithCoverage(ctx, sc)
		return nil
	}); err != nil {
		return nil, err
	}
	checked := time.Now().UTC()
	section := auditorAuditChainEvidence(coverage, verificationErr, checked)
	manifest, attachments, err := compliance.BuildControlEvidence(compliance.ControlEvidenceInput{
		TenantID: actor.TenantID, Reference: control, CollectedAt: checked, Deployment: s.auditorDeploymentIdentity(), Evidence: section,
	})
	if err != nil {
		return nil, err
	}
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
	summary := sealedClientReportTable(actor.TenantID, "compliance-control-summary", "Control evidence result", from, checked,
		plainClientReportColumns([]string{"framework", "guide_version", "control", "checked_at", "source_status", "reason", "signed_package_id"}),
		[][]string{{manifest.Control.Framework, manifest.Control.GuideVersion, control, checked.Format(time.RFC3339Nano), section.Status, section.Reason, manifest.BundleID}})
	summary.Source = "Current tenant audit-chain verification with retained sequence coverage."
	encoded, err := signedReportEvidenceTable(ctx, signed, manifest.BundleID, "compliance-control-"+manifest.BundleID+".json", reporting.CSVTable{
		ID: "compliance-control-evidence", Title: "Complete signed control evidence", TenantID: actor.TenantID,
		Source:       "CSV: concatenate decoded signed_package_base64_chunk cells in ordinal order. PDF: extract the attached JSON. Use verify-bundle --expected-fingerprint with the operator's independently trusted fingerprint.",
		AbsoluteFrom: from, AbsoluteTo: checked,
	})
	if err != nil {
		return nil, err
	}
	return &reportFlowCapture{TenantID: actor.TenantID, ComplianceControl: control,
		controlCapture: &complianceControlCapture{from: from, checked: checked, packageID: manifest.BundleID},
		Tables:         []reporting.CSVTable{summary, encoded}, release: closeCapture}, nil
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
			"The scan checks the retained probectl tenant audit stream at collection time. The assessor combines this evidence with the required assessments."),
		Tables: capture.Tables}, nil
}
