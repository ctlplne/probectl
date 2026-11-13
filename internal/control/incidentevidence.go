// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// handleExportIncidentEvidence creates an immutable, redacted and signed
// package. It repeats tenant-first authorization at the data-access boundary;
// the route-level incident.read check is necessary but not sufficient because
// the package also gathers cited RCA evidence under ai.query.
func (s *Server) handleExportIncidentEvidence(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil || len(s.evidenceSigningKey) == 0 {
		return apierror.Unavailable("signed incident evidence export is unavailable")
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil || p.TenantID == "" {
		return apierror.Unauthorized("authentication required")
	}
	input, err := decodeIncidentEvidenceExport(r)
	if err != nil {
		return err
	}
	if input.Impact != nil || input.Verdict != nil {
		budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
		if err := budget.Validate(); err != nil {
			return apierror.Unavailable("incident evidence query admission is unavailable")
		}
		ctx, cancel := context.WithTimeout(r.Context(), budget.ExecutionLimit)
		defer cancel()
		r = r.WithContext(ctx)
	}
	reason, err := s.decide(r.Context(), p, permAIQuery, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: p.TenantID})
	if err != nil {
		return err
	}
	if reason == auth.DecisionPolicyDeny {
		return apierror.Forbidden("an attribute policy denies AI evidence access")
	}
	if reason != auth.DecisionAllowed {
		return apierror.Forbidden("AI query permission is required to export cited incident evidence")
	}

	incidentID := r.PathValue("id")
	var inc *incident.Incident
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var readErr error
		inc, readErr = (store.Incidents{}).Get(ctx, sc, incidentID)
		return readErr
	}); err != nil {
		return err
	}
	answer, err := s.analyzer.Analyze(r.Context(), p, ai.Question{
		Text: fmt.Sprintf("What caused incident %s affecting %s? Correlate routing, path, flow, device, host, and change evidence.",
			inc.ID, firstNonEmpty(inc.Target, inc.Prefix, inc.Title)),
		Subject: map[string]string{"incident_id": inc.ID, "target": inc.Target, "prefix": inc.Prefix},
		Range:   ai.TimeRange{Start: inc.StartedAt, End: inc.LastSeenAt},
	})
	if err != nil {
		switch {
		case errors.Is(err, ai.ErrEgressDenied):
			return apierror.Forbidden("remote AI model egress is disabled for this tenant; use the builtin/local model or record tenant consent")
		case errors.Is(err, ai.ErrBusy):
			return apierror.RateLimited("the AI assistant is at capacity — retry shortly")
		default:
			return apierror.Unavailable("the cited incident package could not be created")
		}
	}

	pol := incidentEvidenceTenantPolicy(redactionPolicy(s.cfg), p.TenantID)
	var impact *incident.ImpactResponse
	var verdict *incident.FaultVerdict
	var impactPublication, verdictPublication incidentEvidenceFinalizer
	r, retained := s.bindIncidentExportMemory(r, input)
	// One admitted export owns the complete multi-source packaging operation.
	// Source readers retain their own permission and original-document checks.
	if input.Impact != nil || input.Verdict != nil {
		var release func()
		if input.Impact != nil {
			release, err = s.beginIncidentImpactQuery(r.Context(), p)
		} else {
			release, err = s.beginIncidentVerdictQuery(r.Context(), p)
		}
		if err != nil {
			return err
		}
		defer release()
	}
	if input.Impact != nil {
		impact, err = s.exportIncidentImpact(r.Context(), p, inc, *input.Impact, &impactPublication)
		if err != nil {
			return err
		}
	}
	if input.Verdict != nil {
		memory, err := retained.verdictMemory()
		if err != nil {
			return err
		}
		verdict, err = s.exportIncidentVerdict(r.Context(), p, inc, *input.Verdict, memory, &verdictPublication)
		if err != nil {
			return err
		}
	}
	if impact != nil && impactPublication == nil || verdict != nil && verdictPublication == nil {
		return apierror.Unavailable("incident export original-source publication check is unavailable")
	}
	redactedIncident := redactIncidentForShare(*inc, pol, p.TenantID)
	redactedAnswer := redactAnswerForShare(answer, pol, p.TenantID)
	var impactProfile staticReportProfile
	if impact != nil || verdict != nil {
		impactProfile, err = s.staticReportOperation()
		if err != nil {
			return apierror.Unavailable("incident evidence output admission is unavailable")
		}
		impactBytes, err := json.Marshal(struct {
			Impact  *incident.ImpactResponse
			Verdict *incident.FaultVerdict
		}{impact, verdict})
		if err != nil {
			return err
		}
		incidentBytes, err := json.Marshal(redactedIncident)
		if err != nil {
			return err
		}
		if int64(len(impactBytes))+int64(len(incidentBytes)) > impactProfile.budget.MemoryBytes/16 {
			return apierror.Validation("complete incident evidence exceeds configured report rendering memory; increase the report memory allowance")
		}
	}
	manifest, attachments, err := evidence.Build(evidence.BuildInput{
		TenantID: p.TenantID, Incident: redactedIncident, CreatedAt: time.Now().UTC(),
		Conclusion: redactedAnswer.RootCause,
		Grounded:   redactedAnswer.RootCauseGrounded && !redactedAnswer.InsufficientEvidence,
		Impact:     impact,
		Verdict:    verdict,
	})
	if err != nil {
		return apierror.Internal("incident evidence manifest failed").Wrap(err)
	}
	packageJSON, err := evidence.Sign(manifest, attachments, s.evidenceSigningKey)
	if err != nil {
		return apierror.Internal("incident evidence signing failed").Wrap(err)
	}
	if (impact != nil || verdict != nil) && int64(len(packageJSON)) > impactProfile.output.Bytes {
		return apierror.Validation("complete incident evidence exceeds configured report output bytes; increase the report output allowance")
	}
	// These checks use the original retained selectors, not new histories.
	// Keep current export/AI permission checks after encoding and signing too.
	for _, publication := range []incidentEvidenceFinalizer{impactPublication, verdictPublication} {
		if publication != nil {
			if err := publication(r.Context()); err != nil {
				return err
			}
		}
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "incident.evidence_export", manifest.PackageID, map[string]any{
			"incident_id": inc.ID, "contract": evidence.ContractVersion,
			"evidence_count": len(manifest.Evidence), "statements": len(manifest.Statements),
			"impact_included": impact != nil, "verdict_included": verdict != nil,
		})
	}); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/vnd.probectl.evidence+json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="probectl-incident-%s-evidence.json"`, inc.ID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packageJSON)
	return nil
}
