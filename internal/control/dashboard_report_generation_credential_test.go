// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportGenerationRechecksOriginatingCredentialAfterRender(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	owner, sibling := f.tenants[0], f.tenants[1]
	dashboard := uuid(t)
	definition, err := json.Marshal(validDashboardRequest().Definition)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, scope tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, scope, f.roles[tenant], "metrics.read"); err != nil {
				return err
			}
			_, err := (store.DashboardReports{}).CreateView(ctx, scope, store.DashboardViewInput{
				ID: dashboard, OwnerID: f.users[tenant], Name: "Credential publication " + tenant,
				Preset: "operator", Definition: definition,
			})
			return err
		})
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	tokens := store.NewMCPTokens(f.pool)
	ownerToken, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	credentialID, err := tokens.CreateWithLifetime(ctx, owner, f.users[owner], "report-render", crypto.Hash([]byte(ownerToken)), time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := func(tenant, token string) *http.Request {
		t.Helper()
		bound := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		r := httptest.NewRequestWithContext(bound, http.MethodPost, "/v1/dashboard-reports", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		actor := f.server.resolvePrincipal(r)
		if actor == nil || actor.TenantID != tenant {
			t.Fatal("the owning report credential did not authenticate")
		}
		return r.WithContext(auth.WithPrincipal(bound, actor))
	}
	counts := func(tenant string, expected int) {
		t.Helper()
		f.in(tenant, func(ctx context.Context, scope tenancy.Scope) error {
			var artifacts, audits int
			if err := scope.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND dashboard_id=$2`, tenant, dashboard).Scan(&artifacts); err != nil {
				return err
			}
			if err := scope.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='dashboard.report_export'`, tenant).Scan(&audits); err != nil {
				return err
			}
			if artifacts != expected || audits != expected {
				t.Fatalf("report artifacts=%d and publication audits=%d, want %d of each", artifacts, audits, expected)
			}
			return nil
		})
	}
	input := reportGenerateRequest{DashboardID: dashboard, Format: "csv"}
	issued, err := f.server.generateDashboardReport(request(owner, ownerToken), input, renderDashboardReport)
	if err != nil || issued == nil {
		t.Fatal("the same credential did not publish when still valid", err)
	}
	counts(owner, 1)

	artifact, err := f.server.generateDashboardReport(request(owner, ownerToken), input, func(renderContext context.Context, format string, doc reporting.Document) ([]byte, string, error) {
		if doc.TenantScope != owner {
			t.Fatal("the renderer received another tenant's report")
		}
		body, media, err := renderDashboardReport(renderContext, format, doc)
		if err != nil || len(body) == 0 {
			t.Fatal("the report did not produce bytes before credential revocation", err)
		}
		if revoked, err := tokens.RevokeByID(ctx, owner, credentialID); err != nil || !revoked {
			t.Fatal("the originating credential was not revoked during rendering", err)
		}
		return body, media, nil
	})
	if domain, ok := apierror.As(err); !ok || domain.Kind != apierror.KindUnauthorized || artifact != nil {
		t.Fatalf("the revoked credential reached report publication, artifact present: %t, err: %v", artifact != nil, err)
	}
	counts(owner, 1)
	other, err := f.server.generateDashboardReport(request(sibling, f.tokens[sibling]), input, renderDashboardReport)
	if err != nil || other == nil {
		t.Fatal("revocation affected the sibling tenant's report", err)
	}
	counts(sibling, 1)
}
