// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package cmdb_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const (
	serviceNowOwnedKey  = "shared-wire-fixture.example"
	serviceNowTenantEnv = "PROBECTL_CMDB_SERVICENOW_TENANT_ID"
)

type serviceNowFixtureScope struct {
	user, password, recordID string
}

func (s serviceNowFixtureScope) credential() string { return s.user + ":" + s.password }

type serviceNowTableFixture struct {
	scopes  [2]serviceNowFixtureScope
	calls   atomic.Int64
	matched [2]atomic.Int64
	status  atomic.Int32
	wrongCI atomic.Bool
}

// This local stand-in implements the read-only Table API request and response
// used by probectl. Each test credential can see only its own CI even though
// the tenants intentionally use the same lookup key.
// https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html
func (f *serviceNowTableFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	if r.TLS == nil || r.Method != http.MethodGet || r.URL.Path != "/api/now/table/cmdb_ci_server" {
		http.Error(w, "expected a TLS Table API read", http.StatusBadRequest)
		return
	}
	user, password, hasAuth := r.BasicAuth()
	for i, scope := range f.scopes {
		if hasAuth && user == scope.user && password == scope.password {
			f.matched[i].Add(1)
			f.read(w, r, scope, f.scopes[1-i])
			return
		}
	}
	http.Error(w, "fixture credential refused", http.StatusUnauthorized)
}

func (f *serviceNowTableFixture) read(w http.ResponseWriter, r *http.Request, owner, sibling serviceNowFixtureScope) {
	q := r.URL.Query()
	wantQuery := fmt.Sprintf("ip_address=%s^ORfqdn=%s^ORname=%s^ORDERBYsys_id",
		serviceNowOwnedKey, serviceNowOwnedKey, serviceNowOwnedKey)
	if q.Get("sysparm_query") != wantQuery || q.Get("sysparm_offset") != "0" ||
		q.Get("sysparm_query_no_domain") != "false" || q.Get("sysparm_no_count") != "false" ||
		q.Get("sysparm_fields") != "sys_id,name,sys_class_name,ip_address,fqdn" {
		http.Error(w, "fixture query scope refused", http.StatusBadRequest)
		return
	}
	if status := f.status.Load(); status != 0 {
		http.Error(w, "fixture Table API error", int(status))
		return
	}
	id, name, address := owner.recordID, serviceNowOwnedKey, "192.0.2.38"
	if f.wrongCI.Load() {
		id, name, address = sibling.recordID, "unexpected-ci.example", "192.0.2.87"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", "1")
	_ = json.NewEncoder(w).Encode(map[string]any{"result": []map[string]string{{
		"sys_id": id, "name": name, "sys_class_name": "cmdb_ci_server", "ip_address": address, "fqdn": name,
	}}})
}

// Exercise the shipped control binary, verified TLS, actual tenant sessions
// and the RLS ownership lookup, with a stand-in for the vendor Table API.
func TestShippedServiceNowStandInKeepsScopedCredentialsAndRecovers(t *testing.T) {
	fixture := &serviceNowTableFixture{}
	for i := range fixture.scopes {
		pass, err := crypto.Random(24)
		if err != nil {
			t.Fatal(err)
		}
		fixture.scopes[i] = serviceNowFixtureScope{
			user: fmt.Sprintf("table-reader-%d", i), password: hex.EncodeToString(pass), recordID: fmt.Sprintf("%032x", i+1),
		}
	}
	upstream := httptest.NewTLSServer(fixture)
	t.Cleanup(upstream.Close)
	caFile := filepath.Join(t.TempDir(), "servicenow-fixture-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	st := shipped.Start(t, shipped.Options{Name: "servicenow_standin", TenantBand: 3, Env: map[string]string{
		"SSL_CERT_FILE":          caFile,
		"PROBECTL_CMDB_PROVIDER": "servicenow",
		"PROBECTL_CMDB_URL":      upstream.URL,
		"PROBECTL_CMDB_TABLE":    "cmdb_ci_server",
		"PROBECTL_CMDB_SECRET":   fixture.scopes[0].credential(),
		serviceNowTenantEnv:      tenancy.DefaultTenantID.String(),
	}})
	operator := st.OnboardOperator(t, "root@msp-servicenow-fixture.example")
	type lane struct{ ID, Cookie string }
	var lanes [2]lane
	pool := st.ApplicationReadPool(t)
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		name := fmt.Sprintf("ServiceNow stand-in %d", i)
		st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &lanes[i],
			"provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":"servicenow-fixture-%d","name":%q,"isolation_model":"pooled"}`, i, name))
		if lanes[i].ID == "" {
			t.Fatal("ServiceNow stand-in tenant has no ID")
		}
		lanes[i].Cookie = st.SignIn(t, lanes[i].ID, email, name)
		id, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lanes[i].ID))
		if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, s tenancy.Scope) error {
			_, err := (store.Agents{}).Register(ctx, s, id, serviceNowOwnedKey, serviceNowOwnedKey,
				"fixture", crypto.AgentSPIFFEID(lanes[i].ID, id), nil)
			return err
		}); err != nil {
			t.Fatal("seed the tenant's local lookup key through its TLS RLS role", err)
		}
	}

	st.RestartControl(t, "servicenow-owner-a", map[string]string{serviceNowTenantEnv: lanes[0].ID})
	requireServiceNowNoCall(t, st, fixture, lanes[1].Cookie, serviceNowOwnedKey, http.StatusServiceUnavailable)
	requireServiceNowNoCall(t, st, fixture, lanes[0].Cookie, "unowned-ci.example", http.StatusNotFound)

	t.Run("upstream-failure-and-recovery", func(t *testing.T) {
		for _, status := range []int32{http.StatusServiceUnavailable, http.StatusUnauthorized} {
			fixture.status.Store(status)
			before := fixture.matched[0].Load()
			requireServiceNowResult(t, st, lanes[0].Cookie, serviceNowOwnedKey, http.StatusServiceUnavailable, "")
			if fixture.matched[0].Load() != before+1 {
				t.Fatalf("upstream HTTP %d was not exercised with the bound credential", status)
			}
		}
		fixture.status.Store(0)
		fixture.wrongCI.Store(true)
		requireServiceNowResult(t, st, lanes[0].Cookie, serviceNowOwnedKey, http.StatusServiceUnavailable, "")
		fixture.wrongCI.Store(false)
		requireServiceNowResult(t, st, lanes[0].Cookie, serviceNowOwnedKey, http.StatusOK, fixture.scopes[0].recordID)
	})
	requireServiceNowNoCall(t, st, fixture, lanes[1].Cookie, serviceNowOwnedKey, http.StatusServiceUnavailable)

	t.Run("missing-and-malformed-owner", func(t *testing.T) {
		before := fixture.calls.Load()
		for i, owner := range []string{"", "invalid-tenant"} {
			log := st.ServeUntilExit(t, fmt.Sprintf("servicenow-invalid-owner-%d", i), map[string]string{
				"PROBECTL_DEPLOYMENT_PROFILE": "multi-tenant", serviceNowTenantEnv: owner,
			}, 15*time.Second)
			if !strings.Contains(log, serviceNowTenantEnv+" must be a canonical nonzero tenant UUID") {
				t.Fatal("serve did not report absent or malformed ServiceNow credential ownership")
			}
		}
		if fixture.calls.Load() != before {
			t.Fatal("an invalid deployment accessed the Table API")
		}
	})

	t.Run("rebind-to-second-tenant", func(t *testing.T) {
		st.RestartControl(t, "servicenow-owner-b", map[string]string{
			serviceNowTenantEnv: lanes[1].ID, "PROBECTL_CMDB_SECRET": fixture.scopes[1].credential(),
		})
		requireServiceNowNoCall(t, st, fixture, lanes[0].Cookie, serviceNowOwnedKey, http.StatusServiceUnavailable)
		requireServiceNowResult(t, st, lanes[1].Cookie, serviceNowOwnedKey, http.StatusOK, fixture.scopes[1].recordID)
		requireServiceNowNoCall(t, st, fixture, lanes[0].Cookie, serviceNowOwnedKey, http.StatusServiceUnavailable)
		if fixture.matched[1].Load() != 1 {
			t.Fatal("the second tenant did not use its own credential exactly once")
		}
	})
}

func requireServiceNowNoCall(t *testing.T, st *shipped.Stack, fixture *serviceNowTableFixture, cookie, key string, wantStatus int) {
	t.Helper()
	before := fixture.calls.Load()
	requireServiceNowResult(t, st, cookie, key, wantStatus, "")
	if fixture.calls.Load() != before {
		t.Fatal("refused lookup reached the source with a scoped credential")
	}
}

func requireServiceNowResult(t *testing.T, st *shipped.Stack, cookie, key string, wantStatus int, wantID string) {
	t.Helper()
	code, raw := st.Do(t, cookie, http.MethodGet, "/v1/cmdb/lookup?key="+url.QueryEscape(key), nil)
	var reply struct {
		Provider string
		Key      string
		CIs      []cmdb.CI
	}
	if code != wantStatus || json.Unmarshal(raw, &reply) != nil {
		t.Fatalf("served lookup returned HTTP %d, wanted %d with JSON", code, wantStatus)
	}
	if wantID == "" {
		if len(reply.CIs) != 0 || strings.Contains(string(raw), "unexpected-ci.example") {
			t.Fatal("a refused lookup returned Table API content")
		}
		return
	}
	if reply.Provider != "servicenow" || reply.Key != key || len(reply.CIs) != 1 ||
		reply.CIs[0].SysID != wantID || reply.CIs[0].FQDN != key || reply.CIs[0].Class != "cmdb_ci_server" {
		t.Fatal("served lookup lost the configured tenant's expected CI identity and attributes")
	}
}
