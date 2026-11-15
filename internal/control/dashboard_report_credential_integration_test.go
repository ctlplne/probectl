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

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func proveReportRevokedCredential(t *testing.T, f *roleExplanationAPIFixture, tenant, artifact string) {
	t.Helper()
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	id, err := store.NewMCPTokens(f.pool).CreateWithLifetime(ctx, tenant, f.users[tenant], "financial-report-revocation", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://local.test/v1/dashboard-report-artifacts/"+artifact, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.SetPathValue("id", artifact)
	actor := f.server.resolvePrincipal(request)
	if actor == nil {
		t.Fatal("fresh original report credential unavailable")
	}
	request = request.WithContext(auth.WithPrincipal(ctx, actor))
	control := httptest.NewRecorder()
	if err := f.server.downloadDashboardReportArtifact(control, request); err != nil || control.Body.Len() == 0 {
		t.Fatal("valid originating report credential control failed", err)
	}
	// Resolve the credential exactly as middleware does, then revoke it while
	// the admitted request still carries its earlier principal snapshot.
	if revoked, err := store.NewMCPTokens(f.pool).RevokeByID(context.WithoutCancel(ctx), tenant, id); err != nil || !revoked {
		t.Fatal("credential control was not revoked", err)
	}
	if f.server.resolvePrincipal(request) != nil {
		t.Fatal("revoked credential still authenticates; report control is invalid")
	}
	output := httptest.NewRecorder()
	err = f.server.downloadDashboardReportArtifact(output, request)
	if err == nil || output.Body.Len() != 0 {
		t.Fatal("revoked originating report credential published signed financial bytes")
	}
}

func TestReportDownloadRechecksOriginatingCredentialBeforePublishingVerifiedBody(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	for _, tenant := range f.tenants {
		view, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "metrics.read"); err != nil {
				return err
			}
			_, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: view, OwnerID: f.users[tenant], Name: "Credential boundary", Preset: "operator", Definition: json.RawMessage(`{}`)})
			if err != nil {
				return err
			}
			_, err = (store.DashboardReports{}).CreateArtifact(ctx, sc, store.ReportArtifactInput{ID: artifact, DashboardID: view, Format: "csv", MediaType: "text/csv", Filename: "credential.csv", Content: []byte("complete,tenant-owned\n"), GeneratedBy: f.users[tenant], AbsoluteFrom: time.Now().Add(-time.Hour), AbsoluteTo: time.Now(), RedactionState: "tenant policy"})
			return err
		})
		proveReportRevokedCredential(t, f, tenant, artifact)
	}
}
