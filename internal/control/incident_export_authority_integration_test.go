// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The analyzer boundary is modeled; authentication, signing, TLS and paired
// Postgres storage are real. A request-start credential cannot authorize a
// package after that same credential is withdrawn during synthesis.
func TestIncidentExportRechecksOriginatingCredentialAndKeepsSiblingPrivate(t *testing.T) {
	for _, boundary := range []string{"credential_revoked", "permission_withdrawn", "user_disabled", "incident_erased", "incident_changed"} {
		t.Run(boundary, func(t *testing.T) { proveIncidentExportCurrentBoundary(t, boundary) })
	}
}

func proveIncidentExportCurrentBoundary(t *testing.T, boundary string) {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	key, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	f.server.WithEvidenceSigningKey(key)
	model := &pathHealthRCAModel{}
	f.server.analyzer = ai.NewAnalyzer(buildEngineWithPolicyLoader(f.server.cfg, f.pool, f.server.aiPolicyLoader(), f.server.aiSources()), ai.WithModel(model))
	ids := map[string]string{}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permAIQuery, permChangeRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		original, err := BuildCorrelator(f.pool, time.Minute, f.server.log).Ingest(t.Context(), incident.Signal{TenantID: tenant, Plane: "network", Kind: "source-proof", Title: "Original isolated export", Summary: "Scoped original fixture", Target: "192.0.2.7", Severity: incident.SeverityWarning, OccurredAt: time.Now().UTC().Add(-time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		ids[tenant] = original.ID
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	read := func(tenant, id string) (int, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/incidents/"+id+"/exports", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	for _, tenant := range f.tenants {
		code, body := read(tenant, ids[tenant])
		manifest, err := evidence.Verify(body)
		if code != http.StatusOK || err != nil || manifest.Incident.ID != ids[tenant] {
			t.Fatal("current tenant's original export was unavailable", code, err)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	if code, body := read(b, ids[a]); code == http.StatusOK || strings.Contains(string(body), ids[a]) {
		t.Fatal("foreign export selected the other tenant's original")
	}
	model.after = func() {
		model.after = nil
		if boundary == "credential_revoked" {
			if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
				t.Error(err)
			}
			return
		}
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			switch boundary {
			case "permission_withdrawn":
				_, err = sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permAIQuery)
			case "user_disabled":
				_, err = sc.Q.Exec(ctx, `UPDATE users SET status='disabled' WHERE tenant_id=$1 AND id=$2`, a, f.users[a])
			case "incident_changed":
				_, err = sc.Q.Exec(ctx, `UPDATE incidents SET title='current incident after private source withdrawal' WHERE tenant_id=$1 AND id=$2`, a, ids[a])
			case "incident_erased":
				_, err = sc.Q.Exec(ctx, `DELETE FROM incidents WHERE tenant_id=$1 AND id=$2`, a, ids[a])
			default:
				t.Fatal("unknown security boundary")
			}
			return err
		})
	}
	code, body := read(a, ids[a])
	if code == http.StatusOK || strings.Contains(string(body), ids[a]) {
		t.Fatal("withdrawn publication authority exposed its signed original incident", code)
	}
	if model.after != nil {
		t.Fatal("credential-withdrawal boundary did not execute")
	}
	code, body = read(b, ids[b])
	if code != http.StatusOK {
		t.Fatal("primary credential withdrawal changed its sibling's export", code)
	}
	if _, err := evidence.Verify(body); err != nil {
		t.Fatal(err)
	}
}
