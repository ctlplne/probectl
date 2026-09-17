// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

// GET /v1/compliance/auditor-bundle (P7): ONE signed, tenant-scoped export that
// answers what an auditor asks, instead of seven separate downloads they have to
// correlate by hand.
//
// Every section is gathered live at export time rather than read from a cached
// summary — the isolation assertion is re-run, the audit chain is re-verified,
// the self-test status is re-read — because an auditor's question is "is this
// true now", not "was it true when someone last wrote it down". A section that
// cannot be gathered is included and marked unavailable with its reason, so a
// reader can never mistake a control that was not looked at for one that passed.

import (
	"context"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/version"
)

// handleAuditorBundle serves the signed auditor evidence bundle.
func (s *Server) handleAuditorBundle(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if len(s.evidenceSigningKey) == 0 {
		// Refusing is the honest answer: an UNSIGNED auditor bundle is worthless
		// for the purpose it exists for, and emitting one would invite a reader
		// to trust bytes nobody vouched for.
		return apierror.Conflict("auditor bundle requires an evidence signing key (PROBECTL_EVIDENCE_SIGNING_KEY or _FILE)")
	}
	ctx := r.Context()
	sections := []compliance.SectionInput{
		s.auditorIsolationSection(ctx),
		s.auditorSegmentationSection(tid),
		s.auditorAuditChainSection(ctx, tid),
		s.auditorRetentionSection(ctx, tid),
		s.auditorDeletionSection(ctx, tid),
		s.auditorProvenanceSection(),
		s.auditorSelfTestSection(),
	}
	manifest, attachments, err := compliance.BuildAuditorBundle(compliance.AuditorInput{
		TenantID:   tid,
		CreatedAt:  time.Now().UTC(),
		Deployment: s.auditorDeploymentIdentity(),
		Redaction:  "tenant-scoped; no secrets, no other tenant's data",
		Sections:   sections,
	})
	if err != nil {
		return apierror.Internal("auditor bundle assembly failed").Wrap(err)
	}
	raw, err := compliance.SignAuditorBundle(manifest, attachments, s.evidenceSigningKey)
	if err != nil {
		return apierror.Internal("auditor bundle signing failed").Wrap(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="probectl-auditor-bundle.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
	return nil
}

// auditorIsolationSection re-runs the boot-time isolation posture assertion. It
// is the strongest control in the product and the same check that refuses to let
// the control plane start, so re-running it at export time is real evidence
// rather than a restatement of configuration.
func (s *Server) auditorIsolationSection(ctx context.Context) compliance.SectionInput {
	if s.pool == nil {
		return unavailable(compliance.SectionIsolation, "no database pool on this server")
	}
	checked := time.Now().UTC()
	if err := tenancy.AssertIsolationPosture(ctx, s.pool); err != nil {
		return compliance.SectionInput{
			Kind: compliance.SectionIsolation, Status: compliance.StatusFailed,
			Reason: err.Error(),
			Content: map[string]any{
				"assertion": "tenancy.AssertIsolationPosture", "result": "fail",
				"checked_at": checked, "detail": err.Error(),
			},
		}
	}
	return compliance.SectionInput{
		Kind: compliance.SectionIsolation, Status: compliance.StatusVerified,
		Content: map[string]any{
			"assertion":  "tenancy.AssertIsolationPosture",
			"result":     "pass",
			"checked_at": checked,
			"properties": []string{
				"every table carrying tenant_id has FORCE ROW LEVEL SECURITY",
				"pre-tenant lookup tables carry a policy that fails closed once a tenant context is set",
				"no provider policy grants an unconstrained cross-tenant read of tenant data",
				"every table whose policy names the application role has the privilege behind it",
			},
		},
	}
}

// auditorSegmentationSection carries the hash-chained compliance evidence
// document: per-rule results with their framework tags and the coverage caveats
// embedded, which is what makes it readable as segmentation evidence.
func (s *Server) auditorSegmentationSection(tid string) compliance.SectionInput {
	if s.complianceEngine == nil {
		return unavailable(compliance.SectionSegmentation, "compliance engine is not running on this deployment")
	}
	ev, err := s.complianceEngine.Export(tid)
	if err != nil {
		return unavailable(compliance.SectionSegmentation, "compliance export failed: "+err.Error())
	}
	return compliance.SectionInput{Kind: compliance.SectionSegmentation, Status: compliance.StatusVerified, Content: ev}
}

// auditorAuditChainSection re-verifies the tenant's hash-chained audit stream.
func (s *Server) auditorAuditChainSection(ctx context.Context, tid string) compliance.SectionInput {
	if s.pool == nil {
		return unavailable(compliance.SectionAuditChain, "no database pool on this server")
	}
	checked := time.Now().UTC()
	var verr error
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tid)), s.pool, func(tctx context.Context, sc tenancy.Scope) error {
		verr = audit.TenantVerify(tctx, sc)
		return nil
	}); err != nil {
		return unavailable(compliance.SectionAuditChain, "audit stream unreachable: "+err.Error())
	}
	if verr != nil {
		return compliance.SectionInput{
			Kind: compliance.SectionAuditChain, Status: compliance.StatusFailed,
			Reason:  verr.Error(),
			Content: map[string]any{"verification": "audit.TenantVerify", "result": "fail", "checked_at": checked, "detail": verr.Error()},
		}
	}
	return compliance.SectionInput{
		Kind: compliance.SectionAuditChain, Status: compliance.StatusVerified,
		Content: map[string]any{"verification": "audit.TenantVerify", "result": "pass", "checked_at": checked,
			"property": "every record's hash chains to its predecessor; any insertion, deletion or edit breaks verification"},
	}
}

// auditorRetentionSection carries the tenant's retention policy and the status
// the lifecycle engine reports against it — the receipt that a policy is not
// merely configured but being applied.
func (s *Server) auditorRetentionSection(ctx context.Context, tid string) compliance.SectionInput {
	e, err := s.lifecycleEngine()
	if err != nil {
		return unavailable(compliance.SectionRetention, "lifecycle engine unavailable: "+err.Error())
	}
	policy, err := e.RetentionFor(ctx, tid)
	if err != nil {
		return unavailable(compliance.SectionRetention, "retention read failed: "+err.Error())
	}
	status, err := s.lifecycleStatusForPolicy(ctx, tid, policy)
	if err != nil {
		return unavailable(compliance.SectionRetention, "retention status failed: "+err.Error())
	}
	return compliance.SectionInput{Kind: compliance.SectionRetention, Status: compliance.StatusVerified, Content: status}
}

// auditorDeletionSection carries the tenant's verifiable-deletion receipts. A
// deployment that has never been asked to erase a subject has none, and that is
// reported as such rather than as a passing control: nothing was proven.
func (s *Server) auditorDeletionSection(ctx context.Context, tid string) compliance.SectionInput {
	if s.pool == nil {
		return unavailable(compliance.SectionDeletion, "no database pool on this server")
	}
	var receipts []audit.SubjectErasureReceipt
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tid)), s.pool, func(tctx context.Context, sc tenancy.Scope) error {
		var rerr error
		receipts, rerr = audit.SubjectErasureReceipts(tctx, sc, 1000)
		return rerr
	}); err != nil {
		return unavailable(compliance.SectionDeletion, "deletion receipts unreadable: "+err.Error())
	}
	if len(receipts) == 0 {
		return unavailable(compliance.SectionDeletion,
			"no subject erasure has been requested on this tenant, so there is no deletion to prove")
	}
	return compliance.SectionInput{
		Kind: compliance.SectionDeletion, Status: compliance.StatusVerified,
		Content: map[string]any{"receipts": receipts,
			"property": "each receipt is hashed over the per-plane dispositions; a plane that cannot erase keeps the receipt incomplete"},
	}
}

// auditorProvenanceSection names the build. The SBOM itself is a RELEASE
// artifact (docs/releasing.md) and a running control plane cannot regenerate
// one, so this section identifies the build an auditor should fetch it for
// rather than producing a parts list it cannot stand behind.
func (s *Server) auditorProvenanceSection() compliance.SectionInput {
	v := version.Get()
	return compliance.SectionInput{
		Kind: compliance.SectionProvenance, Status: compliance.StatusVerified,
		Content: map[string]any{
			"version": v.Version, "commit": v.Commit, "built_at": v.Date,
			"sbom": map[string]any{
				"generated_by": "the release workflow, not this process",
				"artifact":     "probectl_" + v.Version + "_sbom.spdx.json",
				"note":         "fetch it from the release and verify it with cosign; see docs/ops/verify-artifacts.md",
			},
		},
	}
}

// auditorSelfTestSection carries the cryptographic self-test status read live.
func (s *Server) auditorSelfTestSection() compliance.SectionInput {
	st := crypto.Status()
	if st.ModuleActive && !st.SelfTestPassed {
		return compliance.SectionInput{
			Kind: compliance.SectionSelfTest, Status: compliance.StatusFailed,
			Reason:  "the FIPS module is active and its power-on self-test has not passed",
			Content: st,
		}
	}
	return compliance.SectionInput{Kind: compliance.SectionSelfTest, Status: compliance.StatusVerified, Content: st}
}

func (s *Server) auditorDeploymentIdentity() compliance.DeploymentIdentity {
	v := version.Get()
	st := crypto.Status()
	return compliance.DeploymentIdentity{
		Version:      v.Version,
		Commit:       v.Commit,
		FIPSMode:     st.ModuleActive,
		SBOMArtifact: "probectl_" + v.Version + "_sbom.spdx.json",
	}
}

func unavailable(kind, reason string) compliance.SectionInput {
	return compliance.SectionInput{Kind: kind, Status: compliance.StatusUnavailable, Reason: reason}
}
