// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/httpbody"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const incidentDraftAuditAction = "incident.draft.generate"

type incidentDraftRequest struct {
	Kind evidence.DraftKind `json:"kind"`
	incidentEvidenceExportInput
}

type incidentDraftResponse struct {
	evidence.IncidentDraft
	Model           string `json:"model"`
	Degraded        bool   `json:"degraded"`
	EvidencePackage []byte `json:"evidence_package"`
}

type preparedIncidentDraft struct {
	incident     *incident.Incident
	result       incidentDraftResponse
	publications []incidentEvidenceFinalizer
	signer       string
}

func (p preparedIncidentDraft) checkEvidence(ctx context.Context) error {
	for _, publication := range p.publications {
		if err := publication(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (input incidentDraftRequest) validate(id string, now time.Time) error {
	parsed, err := gouuid.Parse(id)
	if err != nil || parsed == gouuid.Nil || parsed.String() != id {
		return apierror.Validation("an incident ID is required")
	}
	switch input.Kind {
	case evidence.DraftCarrier:
		if input.Carrier == nil || input.Impact != nil || input.Verdict != nil || input.Carrier.From.IsZero() ||
			!input.Carrier.To.After(input.Carrier.From) || input.Carrier.To.After(now) {
			return apierror.Validation("carrier drafts require a past carrier evidence window")
		}
	case evidence.DraftReview, evidence.DraftExecutive:
		if input.Carrier != nil {
			return apierror.Validation("carrier evidence belongs in a carrier ticket draft")
		}
	default:
		return apierror.Validation("select a carrier ticket, postmortem or executive summary draft")
	}
	return nil
}

func (s *Server) beginIncidentDraft(ctx context.Context, actor *auth.Principal) (context.Context, staticReportProfile, func(), error) {
	var none staticReportProfile
	if actor == nil || actor.UserID == "" || actor.TenantID == "" || s.requireMFA && !actor.MFASatisfied {
		return nil, none, nil, apierror.Forbidden("a current tenant user and required MFA are necessary")
	}
	if s.pool == nil || s.fairnessGate == nil || len(s.evidenceSigningKey) == 0 || s.cfg == nil {
		return nil, none, nil, apierror.Unavailable("signed incident drafts are unavailable")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, none, nil, err
	}
	profile, err := s.staticReportOperation()
	if err != nil {
		return nil, none, nil, apierror.Unavailable("incident draft admission is unavailable")
	}
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return nil, none, nil, apierror.RateLimited("the tenant incident draft allowance is busy")
	}
	ctx, cancel := profile.context(ctx)
	ctx = context.WithValue(ctx, incidentImpactExportKey{}, true)
	return ctx, profile, func() {
		cancel()
		release()
	}, nil
}

func (s *Server) readIncidentDraftSource(ctx context.Context, actor *auth.Principal, id string) (*incident.Incident, error) {
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	if status != "active" {
		return nil, apierror.Forbidden("incident draft tenant is inactive")
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	var inc *incident.Incident
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		inc, err = (store.Incidents{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if inc.TenantID != sc.Tenant.String() {
			return apierror.NotFound("incident draft source is unavailable")
		}
		authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, current, err := authority.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		resource := map[string]string{auth.ResourceTenantKey: current.TenantID, "incident_id": inc.ID}
		for _, permission := range []string{permIncidentRead, permAIQuery} {
			if err := s.authorize(ctx, current, permission, auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}
	return inc, nil
}

func (s *Server) prepareIncidentDraft(ctx context.Context, actor *auth.Principal, id string, input incidentDraftRequest, profile staticReportProfile, revalidate func(context.Context, *incident.Incident) error) (preparedIncidentDraft, error) {
	var out preparedIncidentDraft
	inc, err := s.readIncidentDraftSource(ctx, actor, id)
	if err != nil {
		return out, err
	}
	raw, publications, err := s.signIncidentDraftSource(ctx, actor, inc, input)
	if err != nil {
		return out, err
	}
	maxBytes := min(profile.output.Bytes, httpbody.MaxClientResponseBodyBytes)
	if int64(len(raw)) > min(maxBytes, profile.budget.MemoryBytes/16) || 4*((int64(len(raw))+2)/3) >= maxBytes {
		return out, apierror.TooLarge("signed source and draft exceed the configured report allowance")
	}
	public, err := crypto.PublicPEMFromPrivate(s.evidenceSigningKey)
	if err != nil {
		return out, apierror.Unavailable("incident draft signer is unavailable")
	}
	out.signer = evidence.DigestAlgorithm + ":" + hex.EncodeToString(crypto.Hash(public))
	verified, err := evidence.OpenDraftSource(raw, actor.TenantID, inc.ID, out.signer)
	if err != nil {
		return out, apierror.Unavailable("signed incident draft source could not be verified")
	}
	plan, err := verified.Plan(input.Kind)
	if err != nil {
		return out, apierror.Unavailable("signed incident evidence could not be drafted")
	}
	out.incident, out.publications = inc, publications
	if err := out.checkEvidence(ctx); err != nil {
		return preparedIncidentDraft{}, err
	}
	if err := revalidate(ctx, inc); err != nil {
		return preparedIncidentDraft{}, err
	}
	draft, model, degraded, err := s.renderIncidentDraft(ctx, plan, maxBytes)
	if err != nil {
		return out, err
	}
	out.result = incidentDraftResponse{IncidentDraft: draft, Model: model, Degraded: degraded, EvidencePackage: raw}
	return out, ctx.Err()
}

func (s *Server) signIncidentDraftSource(ctx context.Context, actor *auth.Principal, inc *incident.Incident, input incidentDraftRequest) ([]byte, []incidentEvidenceFinalizer, error) {
	if input.Carrier != nil {
		raw, _, publication, err := s.prepareCarrierPackage(ctx, actor, inc, *input.Carrier)
		if err != nil {
			return nil, nil, err
		}
		return raw, []incidentEvidenceFinalizer{publication}, nil
	}
	redaction := incidentEvidenceTenantPolicy(s.incidentEvidenceRedaction(ctx), actor.TenantID)
	redacted := redactIncidentForShare(*inc, redaction, actor.TenantID)
	for _, signal := range redacted.Signals {
		for key := range signal.Attributes {
			if ai.RedactTextForTenant(key, redaction, actor.TenantID) != key {
				delete(signal.Attributes, key)
			}
		}
	}
	built := evidence.BuildInput{TenantID: actor.TenantID, Incident: redacted, CreatedAt: time.Now().UTC()}
	var impactCheck, verdictCheck incidentEvidenceFinalizer
	var memory *incidentExportMemory
	if input.Impact != nil && input.Verdict != nil {
		memory = &incidentExportMemory{limit: flowstore.ExplorerOperationBudget(ctx, s.flowStore).MemoryBytes}
		ctx = context.WithValue(ctx, incidentExportMemoryKey{}, memory)
	}
	if input.Impact != nil {
		var err error
		built.Impact, err = s.exportIncidentImpact(ctx, actor, inc, *input.Impact, &impactCheck)
		if err != nil {
			return nil, nil, err
		}
	}
	if input.Verdict != nil {
		remaining, err := memory.verdictMemory()
		if err != nil {
			return nil, nil, err
		}
		built.Verdict, err = s.exportIncidentVerdict(ctx, actor, inc, *input.Verdict, remaining, &verdictCheck)
		if err != nil {
			return nil, nil, err
		}
	}
	var publications []incidentEvidenceFinalizer
	for _, source := range []struct {
		requested bool
		check     incidentEvidenceFinalizer
	}{{input.Impact != nil, impactCheck}, {input.Verdict != nil, verdictCheck}} {
		if source.requested {
			if source.check == nil {
				return nil, nil, apierror.Unavailable("incident original-source publication check is unavailable")
			}
			publications = append(publications, source.check)
		}
	}
	manifest, attachments, err := evidence.Build(built)
	if err != nil {
		return nil, nil, apierror.Internal("incident draft source could not be packaged").Wrap(err)
	}
	raw, err := evidence.Sign(manifest, attachments, s.evidenceSigningKey)
	if err != nil {
		return nil, nil, apierror.Internal("incident draft source could not be signed").Wrap(err)
	}
	return raw, publications, nil
}

func (s *Server) handleIncidentDraft(w http.ResponseWriter, r *http.Request) error {
	var input incidentDraftRequest
	if err := decodeJSONLimit(r, flow.MaxPlanGrammarBytes, &input); err != nil {
		return err
	}
	id := r.PathValue("id")
	if err := input.validate(id, time.Now().UTC()); err != nil {
		return err
	}
	actor := auth.PrincipalFrom(r.Context())
	ctx, profile, release, err := s.beginIncidentDraft(r.Context(), actor)
	if err != nil {
		return err
	}
	defer release()
	r = r.WithContext(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(15 * time.Second))
	}
	revalidate := func(ctx context.Context, inc *incident.Incident) error {
		return s.revalidateIncidentExport(r.WithContext(ctx), inc)
	}
	prepared, err := s.prepareIncidentDraft(ctx, actor, id, input, profile, revalidate)
	if err != nil {
		return err
	}
	check := func() error {
		if err := prepared.checkEvidence(ctx); err != nil {
			return err
		}
		return revalidate(ctx, prepared.incident)
	}
	if err := check(); err != nil {
		return err
	}
	encoded, err := json.Marshal(prepared.result)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > min(profile.output.Bytes, httpbody.MaxClientResponseBodyBytes) {
		return apierror.TooLarge("complete incident draft exceeds the configured report output allowance")
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return s.recordAudit(ctx, sc, r, incidentDraftAuditAction, prepared.result.PackageID, incidentDraftAuditData(id, prepared.result))
	}); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
	return nil
}

func incidentDraftAuditData(id string, draft incidentDraftResponse) map[string]any {
	return map[string]any{"incident_id": id, "kind": draft.Kind, "model": draft.Model, "degraded": draft.Degraded}
}
