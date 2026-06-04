package control

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/cmdb"
	"github.com/imfeelingtheagi/probectl/internal/incident"
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
