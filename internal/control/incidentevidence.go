// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
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

	pol := redactionPolicy(s.cfg)
	redactedIncident := redactIncidentForShare(*inc, pol, p.TenantID)
	redactedAnswer := redactAnswerForShare(answer, pol, p.TenantID)
	manifest, attachments, err := evidence.Build(evidence.BuildInput{
		TenantID: p.TenantID, Incident: redactedIncident, CreatedAt: time.Now().UTC(),
		Conclusion: redactedAnswer.RootCause,
		Grounded:   redactedAnswer.RootCauseGrounded && !redactedAnswer.InsufficientEvidence,
	})
	if err != nil {
		return apierror.Internal("incident evidence manifest failed").Wrap(err)
	}
	packageJSON, err := evidence.Sign(manifest, attachments, s.evidenceSigningKey)
	if err != nil {
		return apierror.Internal("incident evidence signing failed").Wrap(err)
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, "incident.evidence_export", manifest.PackageID, map[string]any{
			"incident_id": inc.ID, "contract": evidence.ContractVersion,
			"evidence_count": len(manifest.Evidence), "statements": len(manifest.Statements),
		})
	}); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/vnd.probectl.evidence+json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="probectl-incident-%s-evidence.json"`, inc.ID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packageJSON)
	return nil
}
