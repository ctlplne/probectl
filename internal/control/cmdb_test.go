// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/incident"
)

// fakeCMDB resolves one IP and one hostname.
type fakeCMDB struct{}

func (fakeCMDB) Name() string { return "fake" }
func (fakeCMDB) Lookup(_ context.Context, key string) ([]cmdb.CI, error) {
	switch key {
	case "10.0.0.1":
		return []cmdb.CI{{SysID: "abc", Name: "core-sw1", Class: "switch", IPAddress: key}}, nil
	case "db.acme.example":
		return []cmdb.CI{{SysID: "def", Name: "db01", Class: "server", FQDN: key}}, nil
	}
	return nil, nil
}

func cmdbServer() *Server {
	return testServer(fakePinger{}).WithCMDB(cmdb.NewResolver(fakeCMDB{}, time.Minute))
}

func TestCMDBLookupEndpoint(t *testing.T) {
	srv := cmdbServer()
	rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=10.0.0.1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "core-sw1") || !strings.Contains(body, `"provider":"fake"`) {
		t.Fatalf("body = %s", body)
	}

	// Canonicalization applies (hostname case, port stripping).
	rec = do(srv, http.MethodGet, "/v1/cmdb/lookup?key=DB.ACME.EXAMPLE:5432")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "db01") {
		t.Fatalf("hostname lookup = %d %s", rec.Code, rec.Body.String())
	}

	// Invalid keys are 400; unconfigured CMDB is 503.
	if rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=10.0.0.0/24"); rec.Code != http.StatusBadRequest {
		t.Fatalf("cidr key = %d", rec.Code)
	}
	if rec := do(testServer(fakePinger{}), http.MethodGet, "/v1/cmdb/lookup?key=10.0.0.1"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured = %d", rec.Code)
	}
}

// TestIncidentKeysExtraction pins the S40 CMDB correlation contract on the
// incident side: incident + signal targets, with CanonicalKey dropping
// prefixes/garbage during Correlate.
func TestIncidentKeysExtraction(t *testing.T) {
	inc := &incident.Incident{
		ID: "i-1", Target: "10.0.0.1", Prefix: "10.0.0.0/24",
		Signals: []incident.Signal{
			{Target: "db.acme.example"},
			{Target: "10.0.0.1"}, // duplicate of the incident target
			{Target: ""},
		},
	}
	keys := incidentKeys(inc)
	if len(keys) != 4 || keys[0] != "10.0.0.1" || keys[1] != "db.acme.example" {
		t.Fatalf("keys = %v", keys)
	}

	matches := cmdb.NewResolver(fakeCMDB{}, time.Minute).Correlate(context.Background(), keys)
	if len(matches) != 2 {
		t.Fatalf("matches = %+v, want 2 (dedup + drop empties)", matches)
	}
	if matches[0].CIs[0].Name != "core-sw1" || matches[1].CIs[0].Name != "db01" {
		t.Fatalf("correlated CIs = %+v", matches)
	}
}

func TestAgentCIRouteRegistered(t *testing.T) {
	srv := cmdbServer()
	found := map[string]bool{}
	for _, rt := range srv.apiRoutes() {
		switch rt.Pattern {
		case "/v1/agents/{id}/ci":
			found["agent"] = true
			if rt.Permission != permAgentRead {
				t.Errorf("agent CI perm = %q", rt.Permission)
			}
		case "/v1/incidents/{id}/cis":
			found["incident"] = true
			if rt.Permission != permIncidentRead {
				t.Errorf("incident CIs perm = %q", rt.Permission)
			}
		case "/v1/cmdb/lookup":
			found["lookup"] = true
			if rt.Permission != permCMDBRead {
				t.Errorf("lookup perm = %q", rt.Permission)
			}
		}
	}
	for _, k := range []string{"agent", "incident", "lookup"} {
		if !found[k] {
			t.Errorf("route %s missing", k)
		}
	}
}

// mockSNowHTTP is a ServiceNow-shaped test double for the control-level
// correlation path (provider -> resolver -> handler).
func TestCMDBLookupThroughServiceNowShape(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.RawQuery, "10.0.0.9") {
			fmt.Fprint(w, `{"result":[{"sys_id":"xyz","name":"edge-fw1","sys_class_name":"cmdb_ci_firewall","ip_address":"10.0.0.9"}]}`)
			return
		}
		fmt.Fprint(w, `{"result":[]}`)
	}))
	defer ts.Close()

	srv := testServer(fakePinger{}).WithCMDB(cmdb.NewResolver(cmdb.NewServiceNow(ts.URL, "", "u:p"), time.Minute))
	rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=10.0.0.9")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "edge-fw1") {
		t.Fatalf("servicenow-shaped lookup = %d %s", rec.Code, rec.Body.String())
	}
}

// TestCMDBLookupOnlyAnswersForKeysTheTenantOwns (DPR-118): the CMDB is ONE
// deployment-level system shared by every tenant on an MSP-hosted install, and
// this route took an arbitrary key from the query string. On the lab, tenant
// globex-eu read tenant acme-industries' seeded device straight out of the
// operator's NetBox — a tenant could enumerate another tenant's device names,
// sites and IP assignments by guessing. internal/cmdb's own contract says every
// correlation request resolves keys from the caller's own tenant; this route
// did not, and now does.
func TestCMDBLookupOnlyAnswersForKeysTheTenantOwns(t *testing.T) {
	srv := cmdbServer()
	var asked []string
	srv.cmdbKeyOwner = func(_ *http.Request, key string) (bool, error) {
		asked = append(asked, key)
		return key == "10.0.0.1", nil
	}

	if rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=10.0.0.1"); rec.Code != http.StatusOK {
		t.Fatalf("a key the tenant owns must answer: %d %s", rec.Code, rec.Body.String())
	}
	rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=db.acme.example")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("another tenant's key must be 404, got %d %s", rec.Code, rec.Body.String())
	}
	// The refusal must not confirm that the CI exists somewhere. Only the code
	// and message are inspected: the random request id can spell "db01".
	var refusal struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &refusal); err != nil {
		t.Fatalf("refusal body: %v: %s", err, rec.Body.String())
	}
	if said := refusal.Error.Code + " " + refusal.Error.Message; strings.Contains(said, "db01") || strings.Contains(said, "forbidden") {
		t.Errorf("the refusal leaks whether the key exists: %s", rec.Body.String())
	}
	// The ownership question is asked with the canonical key, not the raw one.
	if rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=DB.ACME.EXAMPLE:5432"); rec.Code != http.StatusNotFound {
		t.Fatalf("canonicalized key = %d", rec.Code)
	}
	if len(asked) != 3 || asked[2] != "db.acme.example" {
		t.Errorf("ownership must be checked with the canonical key, got %v", asked)
	}
}

// TestCMDBLookupThroughNetBoxServesStaleWhenDown closes RTA-10: with a NetBox
// provider configured, an OWNED key returns its CI; when NetBox is then down,
// the lookup serves the STALE cache (a down CMDB must not break probectl); a
// FOREIGN key is 404 and never confirms the key exists. The tiny TTL forces the
// second lookup past the fresh-cache window so it exercises the provider-error
// stale-fallback path (internal/cmdb.Resolver.Lookup). Fail-before: making that
// stale branch a no-op turns the NetBox-down lookup into a 503 and fails here.
func TestCMDBLookupThroughNetBoxServesStaleWhenDown(t *testing.T) {
	var down atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/api/ipam/ip-addresses/") {
			// NetBox IP shape (internal/cmdb/netbox.go lookupIP).
			_, _ = w.Write([]byte(`{"results":[{"id":7,"address":"10.0.0.5/32","dns_name":"db-01","assigned_object":{"device":{"name":"db-01","display":"db-01"}}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer ts.Close()

	// 1ns TTL: the first fetch caches, every later lookup is immediately stale,
	// so the NetBox-down lookup below goes through the provider (error) path.
	srv := testServer(fakePinger{}).WithCMDB(cmdb.NewResolver(cmdb.NewNetBox(ts.URL, "nb-token"), time.Nanosecond))
	srv.cmdbKeyOwner = func(_ *http.Request, key string) (bool, error) { return key == "10.0.0.5", nil }

	// Owned key → 200 with the CI resolved from the NetBox double.
	rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=10.0.0.5")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "db-01") {
		t.Fatalf("RTA-10: owned NetBox lookup: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"provider":"netbox"`) {
		t.Fatalf("RTA-10: response must name the netbox provider: %s", rec.Body.String())
	}

	// NetBox down → the stale cache entry is served, still 200 with the CI.
	down.Store(true)
	rec = do(srv, http.MethodGet, "/v1/cmdb/lookup?key=10.0.0.5")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "db-01") {
		t.Fatalf("RTA-10: stale cache not served when NetBox is down: %d %s", rec.Code, rec.Body.String())
	}

	// Foreign key → 404, never confirming the key exists elsewhere.
	if rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=10.9.9.9"); rec.Code != http.StatusNotFound {
		t.Fatalf("RTA-10: foreign key must be 404; got %d %s", rec.Code, rec.Body.String())
	}
}
