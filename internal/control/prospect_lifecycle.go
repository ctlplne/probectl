// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	prospectCreatedAudit   = "lifecycle.prospect_created"
	prospectConvertedAudit = "lifecycle.prospect_converted"
	prospectRevokedAudit   = "lifecycle.prospect_consent_revoked"
)

type startProspectInput struct {
	AssessmentViewID string    `json:"assessment_view_id"`
	AssessmentAt     time.Time `json:"assessment_view_revision"`
	Preparer         string    `json:"preparer"`
	EndsAt           time.Time `json:"ends_at"`
	DestinationID    string    `json:"destination_id"`
	ConfirmTenant    string    `json:"confirm_tenant"`
}

func (s *Server) handleGetProspect(w http.ResponseWriter, r *http.Request) error {
	var out store.ProspectEngagement
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = (store.ProspectEngagements{}).Get(ctx, sc)
		return err
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handleStartProspect(w http.ResponseWriter, r *http.Request) error {
	var in startProspectInput
	if err := decodeJSONLimit(r, 4096, &in); err != nil {
		return err
	}
	out, err := s.startProspect(r, in)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, out)
	return nil
}

func (s *Server) startProspect(r *http.Request, in startProspectInput) (store.ProspectEngagement, error) {
	var out store.ProspectEngagement
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.UserID == "" {
		return out, apierror.Forbidden("a current named account is required")
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	input, err := s.prospectStartTerms(r.Context(), actor, in, at)
	if err != nil {
		return out, err
	}
	err = s.withProspectAuthority(r, input.DestinationID != "", func(ctx context.Context, sc tenancy.Scope) error {
		view, err := (store.DashboardReports{}).GetView(ctx, sc, input.AssessmentViewID, actor.UserID)
		if err != nil {
			return err
		}
		var definition dashboardDefinition
		if view.OwnerID != actor.UserID || !view.UpdatedAt.Equal(input.AssessmentAt) {
			return apierror.Conflict("select an exact owned assessment view revision")
		}
		if err := json.Unmarshal(view.Definition, &definition); err != nil || definition.ClientReport == nil {
			return apierror.Validation("select a saved client report as the assessment view")
		}
		out, err = (store.ProspectEngagements{}).Create(ctx, sc, input)
		if err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, prospectCreatedAudit, sc.Tenant.String(), map[string]any{
			"owner_id": out.OwnerID, "tenant_slug": out.TenantSlug, "revision": out.Revision,
			"starts_at": out.StartsAt, "ends_at": out.EndsAt, "assessment_view_id": out.AssessmentViewID,
			"assessment_view_revision": out.AssessmentAt, "consent_revision": out.ConsentRevision,
			"destination_id": out.DestinationID,
		})
	})
	return out, err
}

func (s *Server) prospectStartTerms(ctx context.Context, actor *auth.Principal, in startProspectInput, at time.Time) (store.ProspectEngagement, error) {
	var empty store.ProspectEngagement
	if in.AssessmentAt.IsZero() || in.AssessmentViewID == "" ||
		in.Preparer == "" || strings.TrimSpace(in.Preparer) != in.Preparer || strings.IndexFunc(in.Preparer, unicode.IsControl) >= 0 {
		return empty, apierror.Validation("an exact assessment view revision and preparer are required")
	}
	if (in.DestinationID == "") != (in.ConfirmTenant == "") {
		return empty, apierror.Validation("scheduled erasure consent requires an exact tenant slug and configured delivery destination")
	}
	if in.DestinationID != "" && actor.ViaBearerToken {
		return empty, apierror.Forbidden("scheduled erasure consent requires an interactive session")
	}
	endsAt := in.EndsAt.UTC().Truncate(time.Microsecond)
	if endsAt.IsZero() && in.DestinationID == "" {
		endsAt = at.AddDate(0, 0, 14)
	}
	if !endsAt.After(at) || (in.DestinationID != "" && !endsAt.Equal(in.EndsAt)) {
		return empty, apierror.Validation("select a future engagement end with at most microsecond precision")
	}
	slug, _, _, err := s.tenantSlugAndMeta(ctx, actor.TenantID)
	if err != nil {
		return empty, err
	}
	if slug == "" {
		return empty, apierror.Unavailable("the current tenant registry is unavailable")
	}
	if in.DestinationID != "" {
		if in.ConfirmTenant != slug || in.DestinationID == reportInboxDestination {
			return empty, apierror.Validation("confirm the exact tenant slug and choose its durable report delivery destination")
		}
		if err := s.validateReportDestination(actor.TenantID, in.DestinationID); err != nil {
			return empty, err
		}
	}
	return store.ProspectEngagement{AssessmentViewID: in.AssessmentViewID, AssessmentAt: in.AssessmentAt.UTC(), Preparer: in.Preparer,
		StartsAt: at, EndsAt: endsAt, DestinationID: in.DestinationID, OwnerID: actor.UserID, TenantSlug: slug}, nil
}

func (s *Server) handleConvertProspect(w http.ResponseWriter, r *http.Request) error {
	return s.decideProspect(w, r, true, prospectConvertedAudit)
}

func (s *Server) handleRevokeProspect(w http.ResponseWriter, r *http.Request) error {
	return s.decideProspect(w, r, false, prospectRevokedAudit)
}

func (s *Server) decideProspect(w http.ResponseWriter, r *http.Request, convert bool, action string) error {
	var in struct {
		Revision int64 `json:"revision"`
	}
	if err := decodeJSONLimit(r, 1024, &in); err != nil {
		return err
	}
	if in.Revision < 1 {
		return apierror.Validation("the exact current engagement revision is required")
	}
	out, err := s.applyProspectDecision(r, in.Revision, convert, action)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) applyProspectDecision(r *http.Request, revision int64, convert bool, action string) (store.ProspectEngagement, error) {
	var out store.ProspectEngagement
	err := s.withProspectAuthority(r, false, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = (store.ProspectEngagements{}).Decide(ctx, sc, revision, convert, time.Now().UTC())
		if err != nil {
			return err
		}
		if out.AssessmentArtifactID != "" {
			if err := (store.DashboardReports{}).CompleteReportEmail(ctx, sc, out.AssessmentArtifactID, "withdrawn", time.Now().UTC()); err != nil {
				return err
			}
		}
		return s.recordAudit(ctx, sc, r, action, sc.Tenant.String(), map[string]any{"prior_revision": revision, "revision": out.Revision})
	})
	return out, err
}

func (s *Server) withProspectAuthority(r *http.Request, needsExport bool, fn func(context.Context, tenancy.Scope) error) error {
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.UserID == "" {
		return apierror.Forbidden("a current named account is required")
	}
	ctx, flush := scopedABACDenial(r.Context())
	defer flush(s)
	return s.inTenant(r.WithContext(ctx), func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.AcquireTenantWriteLease(ctx, sc); err != nil {
			return err
		}
		if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		authority, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, current, err := authority.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		resource := map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}
		if err := s.authorize(ctx, current, permLifecycleErase, auth.RBACGlobal, resource); err != nil {
			return err
		}
		if needsExport {
			if err := s.authorize(ctx, current, permLifecycleExp, auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
		return fn(ctx, sc)
	})
}
