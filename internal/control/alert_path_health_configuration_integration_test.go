// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real served TLS and application-role Postgres/FORCE-RLS. Counter rows and
// issued source identities use the existing modeled path-health fixture.
func TestPathHealthAlertTLSConfigurationKeepsTenantsAndRevokedCredentialOutsideWriter(t *testing.T) {
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAlertRead, permAlertWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	defer socket.Close()
	call := func(tenant, method, path string, value any) (int, []byte) {
		t.Helper()
		var body []byte
		var err error
		if value != nil {
			body, err = json.Marshal(value)
		}
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		request.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	source := func(tenant string) alert.PathHealthSourceInput {
		return alert.PathHealthSourceInput{TestID: proof.tests[tenant], InterfaceID: f.interfaceID, Metric: "probectl.device.if.in.fcs.errors"}
	}
	rules := map[string]alert.Rule{}
	for _, tenant := range f.tenants {
		code, raw := call(tenant, http.MethodPost, "/v1/alerts", alertRequest{Name: "Owned FCS climb", PathHealthSource: ptr(source(tenant))})
		var rule alert.Rule
		if code != http.StatusCreated || json.Unmarshal(raw, &rule) != nil || rule.TenantID != tenant || rule.Metric != alert.PathHealthMetric {
			t.Fatalf("create did not bind the current owned source: %d %s", code, raw)
		}
		rules[tenant] = rule
		code, raw = call(tenant, http.MethodGet, "/v1/alerts/rules/"+rule.ID+"/path-health-source", nil)
		var state alert.PathHealthSourceState
		if code != http.StatusOK || json.Unmarshal(raw, &state) != nil || !state.Configured || state.Source == nil || state.Source.TestID != proof.tests[tenant] || state.Source.InterfaceID != f.interfaceID {
			t.Fatalf("owned source inspection failed: %d %s", code, raw)
		}
		for _, secret := range []string{"read_grants", "owner_user_id", f.tokens[tenant]} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("source inspection exposed its stored credential ceiling")
			}
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	code, raw := call(a, http.MethodGet, "/v1/alerts/rules/"+rules[b].ID+"/path-health-source", nil)
	if code < 400 || strings.Contains(string(raw), proof.tests[b]) {
		t.Fatal("foreign rule source crossed tenant storage isolation", code)
	}
	code, raw = call(a, http.MethodPost, "/v1/alerts", alertRequest{Name: "Foreign source", PathHealthSource: ptr(source(b))})
	if code < 400 || strings.Contains(string(raw), proof.tests[b]) {
		t.Fatal("foreign test became an owned alert source", code)
	}
	// The bearer still has the same principal and live user grants. Revoking
	// that exact credential during the complete source read must prevent save.
	proof.history.after = func() {
		proof.history.after = nil
		if err := store.NewMCPTokens(f.pool).RevokeForUser(t.Context(), a, f.users[a]); err != nil {
			t.Fatal(err)
		}
	}
	code, _ = call(a, http.MethodPost, "/v1/alerts", alertRequest{Name: "Revoked during preview", PathHealthSource: ptr(source(a))})
	if code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Fatal("revoked originating credential reached configuration publication", code)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, "SELECT count(*) FROM alert_rules WHERE tenant_id=$1", a).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatal("failed source publication left a partial alert rule", count)
		}
		return nil
	})
	code, raw = call(b, http.MethodDelete, "/v1/alerts/rules/"+rules[b].ID+"/path-health-source", nil)
	var cleared alert.PathHealthSourceState
	if code != http.StatusOK || json.Unmarshal(raw, &cleared) != nil || cleared.Configured || cleared.Source != nil {
		t.Fatalf("sibling clear failed: %d %s", code, raw)
	}
	f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
		rule, err := (store.AlertRules{}).Get(ctx, sc, rules[b].ID)
		if err == nil && rule.Enabled {
			t.Fatal("cleared source left evaluation enabled")
		}
		return err
	})
}
