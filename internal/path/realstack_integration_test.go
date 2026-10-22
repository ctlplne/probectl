// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package path_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// pathVantageText is what the Path page says about where a trace ran from.
const pathVantageText = "Traced from the control plane, not from an agent"

// TestPathVisualizationRealStack is the real-stack receipt for path
// visualization (F3): a tenant discovers the path of one of its tests through
// the public API, the CLI and the rendered Path page, and reads the latest
// path and its discovery history back through all three for that tenant
// only.
//
// Where the traces run from, stated as the product states it: path discovery
// runs in the CONTROL PLANE (RTP-19; D-45), not on agents. Every path this
// receipt reads must say vantage "control_plane", and the Path page must say
// "Traced from the control plane, not from an agent". Path discovery is a
// synchronous control-plane call (trace, then store), so no bus is involved.
//
// What the trace genuinely exercises: the shipped control plane, unprivileged
// as it ships, tracing 127.0.0.1 over its datagram ICMP socket. That socket
// sees only the destination's echo reply, so the path is ONE real hop, the
// destination, and the measurement-fidelity receipt says so (icmp_datagram,
// destination_only). Intermediate hops (Time Exceeded), MPLS labels and ECMP
// branches need a raw socket (CAP_NET_RAW) and a multi-hop network. That
// path is proven by the path-raw-live lane's Linux namespace fixture
// (TestRunRawMultiHop), not here. Nothing in this receipt is a fixture: every
// hop it asserts was traced.
//
// The stack is the shipped control plane on the four-store profile
// (shipped.Start): PostgreSQL behind the least-privilege serve login, Kafka,
// ClickHouse for the path plane with DB-level tenant scoping on, Prometheus,
// TLS everywhere, the real IdP (production session auth) and an MSP license.
// Tenants A and C are pooled and share the path tables; tenant B is hybrid,
// so its paths live in its own database. All three trace the SAME target,
// 127.0.0.1, so a path read that loses its tenant scope returns another
// tenant's rounds.
//
//  1. Each tenant defines an ICMP test to 127.0.0.1 with the audited
//     private-target override (path discovery applies the test's SSRF guard).
//  2. A discovers through POST /v1/tests/{id}/path and then the Path page's
//     "Discover path" button. B discovers with `probectl test path <id>
//     --body {}`. C discovers three times through the API. Each discovery
//     answers a real one-hop path to 127.0.0.1 traced from the control plane.
//  3. Each tenant's GET /v1/tests/{id}/path and `probectl test path` return
//     that path. GET .../path/history and `probectl test path-history` hold
//     exactly the tenant's own number of rounds (2, 1, 3), each from the
//     control plane. Another tenant's test is not found on any path route.
//     Another tenant's round id selects nothing. The pooled path table holds
//     rows for A and C and none for the hybrid tenant B.
//  4. Each tenant's Path page shows its test and path, says it was traced
//     from the control plane with destination-only visibility, and never
//     shows another tenant's test.
func TestPathVisualizationRealStack(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "pathviz", TenantBand: 4})
	op := st.OnboardOperator(t, "root@msp-pathviz.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)

	A := &pathTenant{slug: "path-acme-" + run, name: "Path Acme", model: "pooled", admin: "ada@acme.example", rounds: 2}
	B := &pathTenant{slug: "path-globex-" + run, name: "Path Globex", model: "hybrid", admin: "bob@globex.example", rounds: 1}
	C := &pathTenant{slug: "path-initech-" + run, name: "Path Initech", model: "pooled", admin: "carla@acme.example", rounds: 3}
	tenants := []*pathTenant{A, B, C}

	// 1. One ICMP test per tenant, all to the same loopback target.
	for i, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark = row.ID, fmt.Sprintf("path%d-%s", i, run)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "test.read", "test.write", "test.allow_private")
		tn.testName = "path icmp " + tn.mark
		code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/tests", map[string]any{
			"name": tn.testName, "type": "icmp", "target": "127.0.0.1", "interval_seconds": 60,
			"timeout_seconds": 3, "enabled": true, "params": map[string]string{"allow_private_targets": "true"},
		})
		var test struct{ ID string }
		if code != http.StatusCreated || json.Unmarshal(raw, &test) != nil || test.ID == "" {
			t.Fatalf("POST /v1/tests as %s = %d: %s", tn.slug, code, raw)
		}
		tn.testID = test.ID
	}

	// 2. Discovery through the API, the console and the CLI.
	A.discoverAPI(t, st)
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/path",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: A.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Path & Topology", A.testName},
		Steps: []testsupport.RenderStep{
			{Click: "Discover path", Expect: []string{"Path discovered", pathVantageText, "destination reached"}},
		},
	})
	var cliDiscovered path.Path
	st.MustCLI(t, B.env(), &cliDiscovered, "test", "path", B.testID, "--body", "{}")
	B.checkPath(t, "probectl test path --body (discover)", &cliDiscovered)
	for range C.rounds {
		C.discoverAPI(t, st)
	}

	// 3. The latest path and its history, per tenant, through the API and
	// the CLI; nothing of another tenant's.
	for _, tn := range tenants {
		var latest path.Path
		tn.get(t, st, "/v1/tests/"+tn.testID+"/path", &latest)
		tn.checkPath(t, "GET /v1/tests/{id}/path", &latest)
		var cliLatest path.Path
		st.MustCLI(t, tn.env(), &cliLatest, "test", "path", tn.testID)
		tn.checkPath(t, "probectl test path", &cliLatest)

		var history, cliHistory struct{ Items []pathstore.Snapshot }
		tn.get(t, st, "/v1/tests/"+tn.testID+"/path/history?limit=100", &history)
		st.MustCLI(t, tn.env(), &cliHistory, "test", "path-history", tn.testID, "--query", "limit=100")
		for name, h := range map[string][]pathstore.Snapshot{"GET .../path/history": history.Items, "probectl test path-history": cliHistory.Items} {
			if len(h) != tn.rounds {
				t.Errorf("%s as %s holds %d rounds, want its own %d", name, tn.slug, len(h), tn.rounds)
			}
			ids := map[string]bool{}
			for i := range h {
				ids[h[i].ID] = true
				tn.checkPath(t, name+" round "+h[i].ID, &h[i].Path)
			}
			if len(ids) != len(h) {
				t.Errorf("%s as %s repeats a round id: %+v", name, tn.slug, ids)
			}
		}
		tn.roundIDs = nil
		for _, r := range history.Items {
			tn.roundIDs = append(tn.roundIDs, r.ID)
		}
	}
	for _, tn := range tenants {
		for _, other := range tenants {
			if other == tn {
				continue
			}
			for _, route := range []string{"/path", "/path/history"} {
				if code, raw := st.Do(t, tn.cookie, http.MethodGet, "/v1/tests/"+other.testID+route, nil); code != http.StatusNotFound {
					t.Errorf("GET /v1/tests/%s%s (%s's test) as %s = %d, want 404: %.200s", other.testID, route, other.slug, tn.slug, code, raw)
				}
			}
			if code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/tests/"+other.testID+"/path", nil); code != http.StatusNotFound {
				t.Errorf("POST /v1/tests/%s/path (%s's test) as %s = %d, want 404: %.200s", other.testID, other.slug, tn.slug, code, raw)
			}
			if out, _, code := st.CLI(tn.env(), "test", "path", other.testID); code == 0 {
				t.Errorf("probectl test path %s (%s's test) as %s succeeded: %.200s", other.testID, other.slug, tn.slug, out)
			}
			if len(other.roundIDs) > 0 {
				var selected struct{ Items []pathstore.Snapshot }
				tn.get(t, st, "/v1/tests/"+tn.testID+"/path/history?round_id="+other.roundIDs[0], &selected)
				if len(selected.Items) != 0 {
					t.Errorf("tenant %s selected %s's round %s by id: %+v", tn.slug, other.slug, other.roundIDs[0], selected.Items)
				}
			}
		}
	}
	for _, tn := range tenants {
		n := pooledPathRows(t, tn.id)
		if tn.model == "pooled" && n == 0 {
			t.Errorf("the pooled path table holds no row of pooled tenant %s", tn.slug)
		}
		if tn.model == "hybrid" && n != 0 {
			t.Errorf("the pooled path table holds %d rows of hybrid tenant %s, whose paths belong in its own database", n, tn.slug)
		}
	}

	// 4. The Path page, as each tenant's admin.
	for _, tn := range tenants {
		page := testsupport.RenderSpec{
			URL:            st.BaseURL + "/ui/path",
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
			TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
			Expect: []string{"Path & Topology", tn.testName, "127.0.0.1", "destination reached",
				pathVantageText, "Destination-only fallback", "ICMP datagram"},
		}
		for _, other := range tenants {
			if other != tn {
				page.Absent = append(page.Absent, other.testName, other.mark)
			}
		}
		testsupport.RenderUI(t, page)
	}
}

type pathTenant struct {
	slug, name, model, admin string
	id, mark, cookie, token  string
	testName, testID         string
	rounds                   int
	roundIDs                 []string
}

func (tn *pathTenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

func (tn *pathTenant) get(t *testing.T, st *shipped.Stack, route string, out any) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodGet, route, nil)
	if code != http.StatusOK || json.Unmarshal(raw, out) != nil {
		t.Fatalf("GET %s as %s = %d: %.300s", route, tn.slug, code, raw)
	}
}

// discoverAPI runs one discovery through POST /v1/tests/{id}/path.
func (tn *pathTenant) discoverAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/tests/"+tn.testID+"/path", nil)
	var p path.Path
	if code != http.StatusOK || json.Unmarshal(raw, &p) != nil {
		t.Fatalf("POST /v1/tests/%s/path as %s = %d: %.300s", tn.testID, tn.slug, code, raw)
	}
	tn.checkPath(t, "POST /v1/tests/{id}/path", &p)
}

// checkPath asserts the real one-hop path an unprivileged control plane
// traces to 127.0.0.1, and that it says where it was traced from.
func (tn *pathTenant) checkPath(t *testing.T, surface string, p *path.Path) {
	t.Helper()
	if p.Vantage != path.VantageControlPlane {
		t.Errorf("%s as %s: vantage = %q, want %q (traces run from the control plane)", surface, tn.slug, p.Vantage, path.VantageControlPlane)
	}
	if p.Target != "127.0.0.1" || p.TargetIP != "127.0.0.1" || p.Mode != "icmp" || !p.DestinationReached {
		t.Errorf("%s as %s: path = target %q ip %q mode %q reached %v, want an ICMP path that reached 127.0.0.1",
			surface, tn.slug, p.Target, p.TargetIP, p.Mode, p.DestinationReached)
	}
	f := p.MeasurementFidelity
	if f == nil || f.ProbeTransport != "icmp" || f.AcquisitionMode != "icmp_datagram" || f.HopVisibility != "destination_only" ||
		f.KernelTimestamping || f.HardwareTimestamping {
		t.Errorf("%s as %s: measurement fidelity = %+v, want the unprivileged datagram receipt (destination only)", surface, tn.slug, f)
	}
	if len(p.Hops) != 1 || len(p.Hops[0].Nodes) != 1 {
		t.Errorf("%s as %s: hops = %+v, want the one destination hop a datagram socket sees", surface, tn.slug, p.Hops)
		return
	}
	n := p.Hops[0].Nodes[0]
	if n.IP != "127.0.0.1" || n.Sent < 1 || n.Received != n.Sent || n.LossRatio != 0 || n.RTTAvgMs < 0 {
		t.Errorf("%s as %s: destination hop = %+v, want every probe answered by 127.0.0.1", surface, tn.slug, n)
	}
}

// pooledPathRows counts the tenant's rows in the pooled hop table.
func pooledPathRows(t *testing.T, tenant string) int {
	t.Helper()
	out, err := shipped.CHQuery(shipped.CHURL(), fmt.Sprintf("SELECT count() FROM probectl_path_hops2 WHERE tenant_id = '%s'", tenant))
	if err != nil {
		t.Fatalf("count the pooled path rows of %s: %v", tenant, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("pooled path row count %q: %v", out, err)
	}
	return n
}
