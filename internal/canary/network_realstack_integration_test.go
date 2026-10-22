// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package canary_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/internal/testsync"
)

// TestNetworkTestsRealStack is the real-stack receipt for network tests (F2),
// scoped to agent-to-service: ICMP echo and TCP connect tests a tenant's
// users define through the public API, the CLI and the rendered Targets &
// Tests page, distributed to that tenant's agents over the signed test-bundle
// pull (beta gate G9), run by the shipped agent against loopback targets, and
// read back through the bus, the stores, the API, the CLI and the console
// for that tenant only. The agent-to-agent mesh (POST /v1/a2a/mesh,
// `probectl a2a start-mesh`) is out of scope: its results do not reach a user
// surface yet (AI-11; PD-7, D-46), so this receipt neither drives nor claims
// it.
//
// The stack is the shipped control plane and agent on the four-store profile
// (shipped.Start): PostgreSQL behind the least-privilege serve login, Kafka
// with strict tenant lanes, ClickHouse, Prometheus, TLS everywhere, the real
// IdP (production session auth), an MSP license and a test-bundle signing
// key. Tenant A is pooled (the shared lane), tenant B hybrid (its own lane).
// Each tenant's agent enrolls over mTLS with a one-time join token, has no
// local canaries, and its own config allows central tests to probe private
// targets, because every target here is on loopback and the operator owns
// both ends. The targets: 127.0.0.1 for ICMP (the agent's unprivileged
// datagram ICMP socket), a TCP listener per tenant that counts the connects
// it accepts, and a closed port for a test that must fail.
//
//  1. Tenant A defines an ICMP test through POST /v1/tests and a TCP test in
//     the rendered Targets & Tests "Create test" dialog, ticking the audited
//     private-target override. Tenant B defines an ICMP and a TCP test with
//     `probectl test create` and a TCP test to the closed port through
//     POST /v1/tests.
//  2. Each agent pulls, verifies and runs only its tenant's tests: every
//     result comes from the tenant's agent with its type's measurements
//     (echoes and RTT, connects and connect time), each TCP listener saw its
//     own tenant's connects, and the closed-port test reports a failure, not
//     a fabricated success. Prometheus holds each test's
//     probectl_probe_success series under the tenant's id.
//  3. Lanes: A's results ride the shared topic, B's its own and never the
//     shared one. Each agent's persisted bundle verifies against the
//     deployment key, names its own tenant and holds exactly its tests.
//  4. API and CLI, per tenant: tests, a test by id (the other tenant's is not
//     found), agents, latest and history results, each holding only the
//     caller's own.
//  5. Console: Targets & Tests lists the tenant's tests and never the other
//     tenant's, each Results dialog shows the agent's measurement (ok, or the
//     closed port's failure), and Admin shows the tenant's agent in sync.
func TestNetworkTestsRealStack(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "network", TenantBand: 4, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "testsync-signing-key.pem"),
	}})
	op := st.OnboardOperator(t, "root@msp-network.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)

	A := &netTenant{slug: "net-acme-" + run, name: "Network Acme", model: "pooled", admin: "ada@acme.example"}
	B := &netTenant{slug: "net-globex-" + run, name: "Network Globex", model: "hybrid", admin: "bob@globex.example"}
	tenants := []*netTenant{A, B}

	for i, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark = row.ID, fmt.Sprintf("net%d-%s", i, run)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "test.read", "test.write", "test.allow_private", "agent.read")
		tn.port = newCountingListener(t)
		tn.agent = uuid.NewString()
		tn.agentName = "net-agent-" + tn.id[:8]
		tn.identity = st.EnrollAgent(t, tn.id, tn.agent, tn.agentName)
		if _, err := os.Stat(filepath.Join(tn.identity, "testsync.pub")); err != nil {
			t.Fatalf("enrollment did not hand %s's agent the test-bundle key: %v", tn.slug, err)
		}
		st.StartAgent(t, tn.identity, tn.agentName, []string{"icmp", "tcp"}, `test_sync:
  enabled: true
  interval: 2s
  allowed_types: [icmp, tcp]
  allow_private_targets: true
`)
	}
	for _, tn := range tenants {
		shipped.Await(t, tn.slug+"'s agent applying its tenant's test set", 90*time.Second, func() bool {
			ts := tn.agentTestSet(t, st)
			return ts != nil && ts.InSync && ts.AppliedVersion > 0
		})
	}

	// 1. Tests through the API, the console and the CLI.
	A.icmp = A.createTestAPI(t, st, "icmp "+A.mark, "icmp", "127.0.0.1", map[string]string{"count": "3"})
	A.tcp = netTest{Name: "tcp ui " + A.mark, Type: "tcp", Target: A.port.addr}
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/targets",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: A.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Targets & Tests", A.icmp.Name},
		Steps: []testsupport.RenderStep{
			{Click: "New test", Expect: []string{"Create test"}},
			{Fill: `[role=dialog] label:text-is("Name") + div input`, Value: A.tcp.Name},
			{Select: `[role=dialog] select:has(option[value="tcp"])`, Value: "tcp"},
			{Fill: `[role=dialog] label:text-is("Target") + div input`, Value: A.tcp.Target},
			{Fill: `[role=dialog] label:text-is("Interval (seconds)") + div input`, Value: "10"},
			{Click: "Allow this test to probe private or loopback addresses", Role: "checkbox", Within: "[role=dialog]"},
			{Click: "Create", Within: "[role=dialog]", Expect: []string{"Test created"}},
		},
	})
	A.tcp.ID = A.findTest(t, st, A.tcp.Name)
	B.icmp = B.createTestCLI(t, st, "icmp "+B.mark, "icmp", "127.0.0.1", "--param", "count=3")
	B.tcp = B.createTestCLI(t, st, "tcp cli "+B.mark, "tcp", B.port.addr)
	B.closed = B.createTestAPI(t, st, "tcp closed "+B.mark, "tcp", closedPort(t), nil)
	A.tests = []netTest{A.icmp, A.tcp}
	B.tests = []netTest{B.icmp, B.tcp, B.closed}

	// 2. Each agent runs its own tenant's tests; results reach the stores.
	// A missing result is reported, not fatal, so the cross-tenant checks
	// below still name a test that reached the wrong agent.
	for _, tn := range tenants {
		if !eventuallyTrue(150*time.Second, func() bool {
			latest := tn.latest(t, st)
			for _, test := range tn.tests {
				if _, ok := latest[test.ID]; !ok {
					return false
				}
			}
			return true
		}) {
			t.Errorf("not every test of %s reported a result within 150s: %+v", tn.slug, tn.latest(t, st))
			continue
		}
		latest := tn.latest(t, st)
		for _, test := range tn.tests {
			if r := latest[test.ID]; r.AgentID != tn.agent {
				t.Errorf("%s's %s result came from agent %q, want its own agent %s", tn.slug, test.Name, r.AgentID, tn.agent)
			}
		}
		if r := latest[tn.icmp.ID]; !r.Success || r.Metrics["packets.sent"] != 3 || r.Metrics["packets.received"] != 3 ||
			r.Metrics["loss.ratio"] != 0 || !hasMetric(r, "rtt.avg.ms") || r.Attributes["network.peer.address"] != "127.0.0.1" {
			t.Errorf("%s's ICMP result = %+v, want 3/3 echoes from 127.0.0.1 with an RTT", tn.slug, r)
		}
		if r := latest[tn.tcp.ID]; !r.Success || r.Metrics["packets.received"] != 3 || !hasMetric(r, "connect.avg.ms") ||
			r.Attributes["server.port"] != tn.port.port() {
			t.Errorf("%s's TCP result = %+v, want 3/3 connects to port %s with a connect time", tn.slug, r, tn.port.port())
		}
		if tn.port.accepted() == 0 {
			t.Errorf("%s's TCP listener %s accepted no connect", tn.slug, tn.port.addr)
		}
		for _, test := range tn.tests {
			shipped.Await(t, "Prometheus's probectl_probe_success series for "+tn.slug+"'s "+test.Name, 60*time.Second, func() bool {
				return promCount(t, fmt.Sprintf(`count(probectl_probe_success{tenant_id=%q,test_id=%q})`, tn.id, test.ID)) > 0
			})
		}
	}
	if r := B.latest(t, st)[B.closed.ID]; r.Success || r.Metrics["loss.ratio"] != 1 || !strings.Contains(r.Error, "TCP connects to "+B.closed.Target+" failed") {
		t.Errorf("the closed-port test's result = %+v, want a failed connect, not a success", r)
	}
	if n := promCount(t, fmt.Sprintf(`max(probectl_probe_success{tenant_id=%q,test_id=%q})`, B.id, B.closed.ID)); n != 0 {
		t.Errorf("Prometheus's probectl_probe_success for the closed-port test = %d, want 0", n)
	}
	if t.Failed() {
		t.FailNow()
	}

	// 3. The lanes, and what each agent received.
	if laneCount(t, "probectl.network.results", A.id) == 0 {
		t.Error("no result of the pooled tenant on the shared lane")
	}
	if n := laneCount(t, "probectl.t-"+B.slug+".network.results", B.id); n == 0 {
		t.Errorf("no result on the hybrid tenant's lane probectl.t-%s.network.results", B.slug)
	}
	if n := laneCount(t, "probectl.network.results", B.id); n != 0 {
		t.Errorf("the hybrid tenant's results rode the shared lane (%d records)", n)
	}
	for _, tn := range tenants {
		b := tn.persistedBundle(t, st)
		got := map[string]string{}
		for _, test := range b.Tests {
			got[test.ID] = test.Target
		}
		want := map[string]string{}
		for _, test := range tn.tests {
			want[test.ID] = test.Target
		}
		if b.TenantID != tn.id || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("agent %s's bundle = tenant %s tests %v, want tenant %s tests %v", tn.agentName, b.TenantID, got, tn.id, want)
		}
	}

	// 4. The public API and CLI, per tenant, holding only the caller's own.
	for _, tn := range tenants {
		other := tn.other(A, B)
		var tests struct{ Items []netTest }
		tn.get(t, st, "/v1/tests", &tests)
		var cliTests []netTest
		st.MustCLI(t, tn.env(), &cliTests, "test", "list")
		for name, list := range map[string][]netTest{"GET /v1/tests": tests.Items, "probectl test list": cliTests} {
			if !sameTests(list, tn.tests) {
				t.Errorf("%s as %s = %+v, want exactly its tests %+v", name, tn.slug, list, tn.tests)
			}
		}
		if code, raw := st.Do(t, tn.cookie, http.MethodGet, "/v1/tests/"+other.icmp.ID, nil); code != http.StatusNotFound {
			t.Errorf("GET /v1/tests/%s (%s's test) as %s = %d, want 404: %.200s", other.icmp.ID, other.slug, tn.slug, code, raw)
		}
		if out, _, code := st.CLI(tn.env(), "test", "get", other.tcp.ID); code == 0 {
			t.Errorf("probectl test get %s (%s's test) as %s succeeded: %.200s", other.tcp.ID, other.slug, tn.slug, out)
		}
		var cliAgents []struct {
			ID      string
			TestSet *netTestSet `json:"test_set"`
		}
		st.MustCLI(t, tn.env(), &cliAgents, "agent", "list")
		if len(cliAgents) != 1 || cliAgents[0].ID != tn.agent || cliAgents[0].TestSet == nil || !cliAgents[0].TestSet.InSync {
			t.Errorf("probectl agent list as %s = %+v, want only its agent, in sync", tn.slug, cliAgents)
		}
		var apiHistory, cliLatest, cliHistory netResults
		tn.get(t, st, "/v1/results/history?window=1h", &apiHistory)
		st.MustCLI(t, tn.env(), &cliLatest, "result", "latest")
		st.MustCLI(t, tn.env(), &cliHistory, "result", "history", "--query", "window=1h")
		for name, rs := range map[string]netResults{
			"GET /v1/results/history": apiHistory, "probectl result latest": cliLatest, "probectl result history": cliHistory,
		} {
			for _, test := range tn.tests {
				if rs.count(test.ID) == 0 {
					t.Errorf("%s as %s holds no result of its test %s", name, tn.slug, test.Name)
				}
			}
			foreign := 0
			for _, r := range rs.Items {
				if r.AgentID == other.agent || other.owns(r.Attributes["probectl.test.id"]) {
					foreign++
				}
			}
			if foreign > 0 {
				t.Errorf("%s as %s holds %d results of %s's tests or agent", name, tn.slug, foreign, other.slug)
			}
		}
		for id := range tn.latest(t, st) {
			if other.owns(id) {
				t.Errorf("GET /v1/results/latest as %s holds %s's test %s", tn.slug, other.slug, id)
			}
		}
	}

	// 5. The console, as each tenant's admin.
	for _, tn := range tenants {
		other := tn.other(A, B)
		console := testsupport.RenderSpec{
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
			TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		}
		targets := console
		targets.URL = st.BaseURL + "/ui/targets"
		targets.Expect = []string{"Targets & Tests"}
		for _, test := range tn.tests {
			targets.Expect = append(targets.Expect, test.Name)
		}
		for _, test := range other.tests {
			targets.Absent = append(targets.Absent, test.Name)
		}
		targets.Absent = append(targets.Absent, other.mark, other.agent)
		targets.Steps = []testsupport.RenderStep{
			{Click: "Results for " + tn.icmp.Name, Expect: []string{tn.icmp.Name + " — latest results", tn.agent, "ok", "3/3 received", "RTT"}},
			{Click: "Close dialog", Gone: true},
			{Click: "Results for " + tn.tcp.Name, Expect: []string{tn.tcp.Name + " — latest results", tn.agent, "ok", "3/3 received", "Connect"}},
			{Click: "Close dialog", Gone: true},
		}
		if tn == B {
			targets.Steps = append(targets.Steps, testsupport.RenderStep{
				Click: "Results for " + B.closed.Name, Expect: []string{B.agent, "failed", "TCP connects to " + B.closed.Target + " failed", "0/3 received"},
			})
		}
		testsupport.RenderUI(t, targets)
		admin := console
		admin.URL = st.BaseURL + "/ui/admin"
		admin.Expect = []string{tn.agentName, "In sync"}
		admin.Absent = []string{other.agentName, "None applied", "Behind"}
		testsupport.RenderUI(t, admin)
	}
}

type netTenant struct {
	slug, name, model, admin       string
	id, mark, cookie, token, agent string
	agentName, identity            string
	port                           *countingListener
	icmp, tcp, closed              netTest
	tests                          []netTest
}

type netTest struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Target string `json:"target"`
}

type netTestSet struct {
	AppliedVersion uint64 `json:"applied_version"`
	CurrentVersion uint64 `json:"current_version"`
	InSync         bool   `json:"in_sync"`
}

type netResult struct {
	AgentID    string             `json:"agent_id"`
	Type       string             `json:"type"`
	Success    bool               `json:"success"`
	Error      string             `json:"error"`
	Metrics    map[string]float64 `json:"metrics"`
	Attributes map[string]string  `json:"attributes"`
}

type netResults struct {
	Items []netResult `json:"items"`
}

func (r netResults) count(testID string) int {
	n := 0
	for _, it := range r.Items {
		if it.Attributes["probectl.test.id"] == testID {
			n++
		}
	}
	return n
}

func hasMetric(r netResult, name string) bool {
	v, ok := r.Metrics[name]
	return ok && v >= 0
}

func sameTests(got, want []netTest) bool {
	if len(got) != len(want) {
		return false
	}
	ids := map[string]bool{}
	for _, test := range got {
		ids[test.ID] = true
	}
	for _, test := range want {
		if !ids[test.ID] {
			return false
		}
	}
	return true
}

func (tn *netTenant) other(a, b *netTenant) *netTenant {
	if tn == a {
		return b
	}
	return a
}

func (tn *netTenant) owns(testID string) bool {
	for _, test := range tn.tests {
		if test.ID == testID {
			return true
		}
	}
	return false
}

func (tn *netTenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

func (tn *netTenant) get(t *testing.T, st *shipped.Stack, path string, out any) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodGet, path, nil)
	if code != http.StatusOK || json.Unmarshal(raw, out) != nil {
		t.Fatalf("GET %s as %s = %d: %.300s", path, tn.slug, code, raw)
	}
}

// createTestAPI defines a test through POST /v1/tests with the audited
// private-target override (every target here is on loopback).
func (tn *netTenant) createTestAPI(t *testing.T, st *shipped.Stack, name, kind, target string, params map[string]string) netTest {
	t.Helper()
	p := map[string]string{"allow_private_targets": "true"}
	for k, v := range params {
		p[k] = v
	}
	code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": name, "type": kind, "target": target, "interval_seconds": 10,
		"timeout_seconds": 3, "enabled": true, "params": p,
	})
	var test netTest
	if code != http.StatusCreated || json.Unmarshal(raw, &test) != nil || test.ID == "" {
		t.Fatalf("POST /v1/tests (%s) as %s = %d: %s", name, tn.slug, code, raw)
	}
	return test
}

// createTestCLI defines a test through `probectl test create`.
func (tn *netTenant) createTestCLI(t *testing.T, st *shipped.Stack, name, kind, target string, params ...string) netTest {
	t.Helper()
	args := append([]string{"test", "create", "--name", name, "--type", kind, "--target", target,
		"--interval", "10", "--timeout", "3", "--param", "allow_private_targets=true"}, params...)
	var test netTest
	st.MustCLI(t, tn.env(), &test, args...)
	if test.ID == "" {
		t.Fatalf("probectl test create (%s) as %s returned no id", name, tn.slug)
	}
	return test
}

// findTest is the id of the tenant's test with that name.
func (tn *netTenant) findTest(t *testing.T, st *shipped.Stack, name string) string {
	t.Helper()
	var tests struct{ Items []netTest }
	tn.get(t, st, "/v1/tests", &tests)
	for _, test := range tests.Items {
		if test.Name == name {
			return test.ID
		}
	}
	t.Fatalf("tenant %s has no test named %q after the console created it: %+v", tn.slug, name, tests.Items)
	return ""
}

// latest is the tenant's newest result per test, keyed by test id.
func (tn *netTenant) latest(t *testing.T, st *shipped.Stack) map[string]netResult {
	t.Helper()
	var out netResults
	tn.get(t, st, "/v1/results/latest", &out)
	m := map[string]netResult{}
	for _, r := range out.Items {
		if id := r.Attributes["probectl.test.id"]; id != "" {
			m[id] = r
		}
	}
	return m
}

// agentTestSet is GET /v1/agents' test_set for the tenant's one agent.
func (tn *netTenant) agentTestSet(t *testing.T, st *shipped.Stack) *netTestSet {
	t.Helper()
	var agents struct {
		Items []struct {
			ID      string      `json:"id"`
			TestSet *netTestSet `json:"test_set"`
		}
	}
	tn.get(t, st, "/v1/agents", &agents)
	if len(agents.Items) > 1 {
		t.Fatalf("GET /v1/agents as %s lists %d agents, want only its own", tn.slug, len(agents.Items))
	}
	if len(agents.Items) == 0 || agents.Items[0].ID != tn.agent {
		return nil
	}
	return agents.Items[0].TestSet
}

// persistedBundle is the bundle the agent verified and saved, verified again
// here against the deployment key enrollment gave the agent.
func (tn *netTenant) persistedBundle(t *testing.T, st *shipped.Stack) *testsync.Bundle {
	t.Helper()
	signed, err := os.ReadFile(filepath.Join(st.Dir, "buffer-"+tn.agentName, "testsync", "bundle.json"))
	if err != nil {
		t.Fatalf("agent %s persisted no verified bundle: %v", tn.agentName, err)
	}
	pub, err := os.ReadFile(filepath.Join(tn.identity, "testsync.pub"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := testsync.Verify(signed, pub, 0)
	if err != nil {
		t.Fatalf("agent %s's persisted bundle does not verify against the deployment key: %v", tn.agentName, err)
	}
	return b
}

// countingListener is a loopback TCP service that accepts and closes every
// connect, counting them: the target's own record of the probes it saw.
type countingListener struct {
	addr string
	n    atomic.Int64
}

func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	c := &countingListener{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.n.Add(1)
			_ = conn.Close()
		}
	}()
	return c
}

func (c *countingListener) accepted() int64 { return c.n.Load() }

func (c *countingListener) port() string {
	_, port, _ := net.SplitHostPort(c.addr)
	return port
}

// closedPort is a loopback address with nothing listening on it.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// eventuallyTrue polls fn until it holds or within elapses.
func eventuallyTrue(within time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(within)
	for {
		if fn() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
}
