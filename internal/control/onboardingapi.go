// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type onboardingProgressResponse struct {
	AgentEnrollTokenCreated bool `json:"agent_enroll_token_created"`
	AgentRegistered         bool `json:"agent_registered"`
	FirstTestCreated        bool `json:"first_test_created"`
	ScimTokenCreated        bool `json:"scim_token_created"`
}

// handleOnboardingProgress serves the first-run checklist from persisted,
// tenant-scoped rows. It never returns one-time token secrets; it only answers
// whether the tenant has crossed each setup milestone.
func (s *Server) handleOnboardingProgress(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.Unavailable("onboarding progress store is not configured")
	}
	var out onboardingProgressResponse
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		if out.AgentEnrollTokenCreated, err = store.NewEnrollTokens(s.pool).CreatedScoped(ctx, sc); err != nil {
			return err
		}
		if out.AgentRegistered, err = (store.Agents{}).Exists(ctx, sc); err != nil {
			return err
		}
		if out.FirstTestCreated, err = (store.Tests{}).Exists(ctx, sc); err != nil {
			return err
		}
		out.ScimTokenCreated, err = store.NewScimTokens(s.pool).CreatedScoped(ctx, sc)
		return err
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
