// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type mcpProspectEngagementBackend struct{ server *Server }

func (b mcpProspectEngagementBackend) ReadProspectEngagement(ctx context.Context, actor *auth.Principal) (store.ProspectEngagement, error) {
	var result store.ProspectEngagement
	r, err := b.prospectRequest(ctx, actor, http.MethodGet, "/v1/lifecycle/prospect")
	if err != nil {
		return result, err
	}
	err = b.server.withProspectAuthority(r, false, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = (store.ProspectEngagements{}).Get(ctx, sc)
		if err != nil {
			return err
		}
		return b.server.recordAudit(ctx, sc, r, "lifecycle.prospect_read", sc.Tenant.String(), map[string]any{"transport": "mcp", "revision": result.Revision})
	})
	return result, err
}

func (b mcpProspectEngagementBackend) StartProspectEngagement(ctx context.Context, actor *auth.Principal, input mcp.ProspectEngagementStart) (store.ProspectEngagement, error) {
	r, err := b.prospectRequest(ctx, actor, http.MethodPost, "/v1/lifecycle/prospect")
	if err != nil {
		return store.ProspectEngagement{}, err
	}
	return b.server.startProspect(r, startProspectInput{AssessmentViewID: input.AssessmentViewID,
		AssessmentAt: input.AssessmentAt, Preparer: input.Preparer, EndsAt: input.EndsAt})
}

func (b mcpProspectEngagementBackend) DecideProspectEngagement(ctx context.Context, actor *auth.Principal, revision int64, convert bool) (store.ProspectEngagement, error) {
	path, action := "/v1/lifecycle/prospect/revoke-consent", prospectRevokedAudit
	if convert {
		path, action = "/v1/lifecycle/prospect/convert", prospectConvertedAudit
	}
	r, err := b.prospectRequest(ctx, actor, http.MethodPost, path)
	if err != nil {
		return store.ProspectEngagement{}, err
	}
	return b.server.applyProspectDecision(r, revision, convert, action)
}

func (b mcpProspectEngagementBackend) prospectRequest(ctx context.Context, actor *auth.Principal, method, path string) (*http.Request, error) {
	if b.server == nil || actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, apierror.Forbidden("a current prospect tenant and named account are required")
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != actor.TenantID {
		return nil, apierror.Forbidden("the current prospect tenant scope differs")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	if b.server.cluster != nil {
		if ok, _ := b.server.cluster.WriterUsableNow(ctx); !ok {
			return nil, apierror.Unavailable("writer unavailable")
		}
	}
	return http.NewRequestWithContext(auth.WithPrincipal(ctx, actor), method, path, nil)
}
