// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package canary_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// TestSyntheticProbesRealStack is the real-stack receipt for HTTP tests (F4),
// DNS tests (F5) and voice/RTP tests (F21): tests defined through the public
// API and CLI, run by the shipped agent, carried over the bus into the stores,
// and read back through the API, the CLI and the console, for two tenants on
// two lanes. It also drives the canary agent (F1) and the control plane's
// REST, gRPC and CLI surfaces (F10); those two bind once the agent takes its
// tests from the control plane rather than its own configuration.
//
// The stack is the shipped control plane and agent on the full four-store
// profile: PostgreSQL behind the least-privilege serve login, Kafka with strict
// tenant lanes, ClickHouse for every plane, Prometheus, a filesystem object
// store, TLS everywhere, the real IdP, MSP license. Tenant A is pooled (the
// shared lane), tenant B hybrid (a namespaced lane). The targets are local
// stand-ins speaking the real protocols: an HTTP page, a DNS server
// (github.com/miekg/dns) and an RTP echo.
//
//  1. Each tenant's admin defines an HTTP test through POST /v1/tests and a
//     DNS and a voice test through `probectl test create`. Its shipped
//     agent, enrolled with a one-time join token over mTLS, runs the three
//     tests by id (agents take tests from local configuration; there is no
//     config push, docs/adr/config-push.md).
//  2. Results reach the stores: the API's latest and history views carry each
//     test's successful result with its type's metrics (HTTP status and
//     timings, the DNS answer, MOS and R-factor), and Prometheus holds each
//     test's probectl_probe_success series under the tenant's id.
//  3. The public surfaces, per tenant: GET /v1/tests, /v1/agents, /v1/me and
//     /v1/results/latest|history, and `probectl test list`, `agent list`,
//     `result latest`, `result history` and `me show`, each holding only the
//     caller's tests, agent and results.
//  4. The console: Targets & Tests lists the tenant's three tests, each test's
//     Results view shows its agent's ok result, Admin lists its agent, and the
//     API docs page loads the control plane's OpenAPI. The other tenant's
//     tests never render.
func TestSyntheticProbesRealStack(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "synthetic", TenantBand: 4})
	op := st.OnboardOperator(t, "root@msp-synthetic.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "checkout ok for "+r.URL.Query().Get("for"))
	}))
	t.Cleanup(page.Close)
	dnsAddr := serveDNSAnswers(t, "203.0.113.53")
	echo := serveRTPEcho(t)

	A := &synthTenant{slug: "syn-acme-" + run, name: "Synthetic Acme", model: "pooled", admin: "ada@acme.example"}
	B := &synthTenant{slug: "syn-globex-" + run, name: "Synthetic Globex", model: "hybrid", admin: "bob@globex.example"}
	tenants := []*synthTenant{A, B}

	// 1. Tests through the API and the CLI, run by each tenant's shipped agent.
	for i, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark = row.ID, fmt.Sprintf("syn%d-%s", i, run)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "test.read", "test.write", "test.allow_private", "agent.read")
		tn.http = tn.createTest(t, st, "http", page.URL+"/checkout?for="+tn.mark)
		tn.dns = tn.createTestCLI(t, st, "dns", tn.mark+".example.test", "--param", "server="+dnsAddr, "--param", "transport=udp")
		tn.voice = tn.createTestCLI(t, st, "voice", echo)
		tn.agent = uuid.NewString()
		tn.agentName = "syn-agent-" + tn.id[:8]
		st.StartAgent(t, st.EnrollAgent(t, tn.id, tn.agent, tn.agentName), tn.agentName, []string{"http", "dns", "voice"},
			fmt.Sprintf(`canaries:
  - test_id: %q
    type: http
    target: %q
    interval: 2s
    timeout: 5s
    params:
      allow_private_targets: "true"
  - test_id: %q
    type: dns
    target: %q
    interval: 2s
    timeout: 3s
    params:
      server: %q
      transport: udp
      allow_private_targets: "true"
  - test_id: %q
    type: voice
    target: %q
    interval: 3s
    timeout: 5s
    params:
      duration_seconds: "1"
      allow_private_targets: "true"
`, tn.http.ID, tn.http.Target, tn.dns.ID, tn.dns.Target, dnsAddr, tn.voice.ID, tn.voice.Target))
	}

	// 2. Results in the stores, for every test of every tenant.
	for _, tn := range tenants {
		shipped.Await(t, tn.slug+"'s three test results", 120*time.Second, func() bool {
			got := tn.latest(t, st)
			return got[tn.http.ID].Success && got[tn.dns.ID].Success && got[tn.voice.ID].Success
		})
		latest := tn.latest(t, st)
		if r := latest[tn.http.ID]; r.Metrics["http.status"] != 200 || r.AgentID != tn.agent {
			t.Errorf("%s's HTTP result = %+v, want status 200 from agent %s", tn.slug, r, tn.agent)
		}
		if r := latest[tn.dns.ID]; r.Attributes["probectl.dns.answer"] != "A 203.0.113.53" || r.Metrics["dns.answers"] != 1 {
			t.Errorf("%s's DNS result = %+v, want the A answer", tn.slug, r)
		}
		if r := latest[tn.voice.ID]; r.Metrics["voice.mos"] < 4 || r.Metrics["voice.r_factor"] <= 0 {
			t.Errorf("%s's voice result = %+v, want a clean call's MOS and R-factor", tn.slug, r)
		}
		for _, test := range []synthTest{tn.http, tn.dns, tn.voice} {
			// The TSDB rides its own consumer, behind the latest-result view.
			shipped.Await(t, "Prometheus's probectl_probe_success series for "+tn.slug+"'s "+test.Type+" test", 60*time.Second, func() bool {
				return promCount(t, fmt.Sprintf(`count(probectl_probe_success{tenant_id=%q,test_id=%q})`, tn.id, test.ID)) > 0
			})
		}
	}

	// Two lanes: A's results ride the shared topic; B's its own, never the
	// shared one.
	if laneCount(t, "probectl.network.results", A.id) == 0 {
		t.Error("no result of the pooled tenant on the shared lane")
	}
	if n := laneCount(t, "probectl.t-"+B.slug+".network.results", B.id); n == 0 {
		t.Errorf("no result on the hybrid tenant's lane probectl.t-%s.network.results", B.slug)
	}
	if n := laneCount(t, "probectl.network.results", B.id); n != 0 {
		t.Errorf("the hybrid tenant's results rode the shared lane (%d records)", n)
	}

	// 3. The public API and CLI, per tenant, holding only the caller's own.
	for _, tn := range tenants {
		other := B
		if tn == B {
			other = A
		}
		var tests struct{ Items []synthTest }
		tn.get(t, st, "/v1/tests", &tests)
		if ids := testIDs(tests.Items); !ids[tn.http.ID] || !ids[tn.dns.ID] || !ids[tn.voice.ID] || ids[other.http.ID] {
			t.Errorf("GET /v1/tests as %s = %v", tn.slug, ids)
		}
		var cliTests []synthTest
		st.MustCLI(t, tn.env(), &cliTests, "test", "list")
		if ids := testIDs(cliTests); len(ids) != 3 || !ids[tn.dns.ID] {
			t.Errorf("probectl test list as %s = %v, want its three tests", tn.slug, ids)
		}
		var agents struct {
			Items []struct{ ID, Name string }
		}
		var cliAgents []struct{ ID, Name string }
		tn.get(t, st, "/v1/agents", &agents)
		st.MustCLI(t, tn.env(), &cliAgents, "agent", "list")
		for name, list := range map[string][]struct{ ID, Name string }{"GET /v1/agents": agents.Items, "probectl agent list": cliAgents} {
			if len(list) != 1 || list[0].ID != tn.agent {
				t.Errorf("%s as %s = %+v, want only agent %s", name, tn.slug, list, tn.agent)
			}
		}
		var cliLatest, cliHistory, history synthResults
		st.MustCLI(t, tn.env(), &cliLatest, "result", "latest")
		st.MustCLI(t, tn.env(), &cliHistory, "result", "history", "--query", "window=1h")
		tn.get(t, st, "/v1/results/history?window=1h", &history)
		if !cliLatest.has(tn.http.ID) || !cliLatest.has(tn.voice.ID) || cliLatest.has(other.http.ID) || cliLatest.has(other.voice.ID) {
			t.Errorf("probectl result latest as %s does not hold exactly its own HTTP and voice results", tn.slug)
		}
		for name, h := range map[string]synthResults{"GET /v1/results/history": history, "probectl result history": cliHistory} {
			if h.count(tn.dns.ID) < 2 || h.has(other.dns.ID) {
				t.Errorf("%s as %s holds %d of its DNS results (want a history) or the other tenant's", name, tn.slug, h.count(tn.dns.ID))
			}
		}
		var me struct {
			TenantID string `json:"tenant_id"`
			Email    string `json:"email"`
		}
		tn.get(t, st, "/v1/me", &me)
		var cliMe struct {
			TenantID string `json:"tenant_id"`
		}
		st.MustCLI(t, tn.env(), &cliMe, "me", "show")
		if me.TenantID != tn.id || me.Email != tn.admin || cliMe.TenantID != tn.id {
			t.Errorf("GET /v1/me / probectl me show as %s = %+v / %+v", tn.slug, me, cliMe)
		}
	}

	// 4. The console, as each tenant's admin.
	for _, tn := range tenants {
		other := B
		if tn == B {
			other = A
		}
		console := testsupport.RenderSpec{
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
			TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		}
		targets := console
		targets.URL = st.BaseURL + "/ui/targets"
		targets.Expect = []string{"Targets & Tests", tn.http.Name, tn.dns.Name, tn.voice.Name}
		targets.Absent = []string{other.http.Name, other.dns.Name, other.voice.Name}
		for _, test := range []synthTest{tn.http, tn.dns, tn.voice} {
			targets.Steps = append(targets.Steps,
				testsupport.RenderStep{Click: "Results for " + test.Name, Expect: []string{test.Name + " — latest results", tn.agent, "ok"}},
				testsupport.RenderStep{Click: "Close dialog", Gone: true})
		}
		testsupport.RenderUI(t, targets)
		admin := console
		admin.URL = st.BaseURL + "/ui/admin"
		admin.Expect = []string{tn.agentName}
		admin.Absent = []string{other.agentName}
		testsupport.RenderUI(t, admin)
	}
	docs := testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/docs/api",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: A.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"API docs", "probectl control-plane API"},
	}
	testsupport.RenderUI(t, docs)
}

type synthTenant struct {
	slug, name, model, admin       string
	id, mark, cookie, token, agent string
	agentName                      string
	http, dns, voice               synthTest
}

type synthTest struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Target string `json:"target"`
}

type synthResult struct {
	AgentID    string             `json:"agent_id"`
	Type       string             `json:"type"`
	Success    bool               `json:"success"`
	Metrics    map[string]float64 `json:"metrics"`
	Attributes map[string]string  `json:"attributes"`
}

type synthResults struct {
	Items []synthResult `json:"items"`
}

func (r synthResults) count(testID string) int {
	n := 0
	for _, it := range r.Items {
		if it.Attributes["probectl.test.id"] == testID {
			n++
		}
	}
	return n
}

func (r synthResults) has(testID string) bool { return r.count(testID) > 0 }

func (tn *synthTenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

// createTestCLI defines a test through `probectl test create`.
func (tn *synthTenant) createTestCLI(t *testing.T, st *shipped.Stack, kind, target string, params ...string) synthTest {
	t.Helper()
	args := append([]string{"test", "create", "--name", kind + " " + tn.mark, "--type", kind, "--target", target,
		"--interval", "2", "--timeout", "5", "--param", "allow_private_targets=true"}, params...)
	var test synthTest
	st.MustCLI(t, tn.env(), &test, args...)
	if test.ID == "" {
		t.Fatalf("probectl test create (%s) as %s returned no id", kind, tn.slug)
	}
	return test
}

func (tn *synthTenant) createTest(t *testing.T, st *shipped.Stack, kind, target string) synthTest {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": kind + " " + tn.mark, "type": kind, "target": target, "interval_seconds": 2,
		"timeout_seconds": 5, "enabled": true, "params": map[string]string{"allow_private_targets": "true"},
	})
	var test synthTest
	if code != http.StatusCreated || json.Unmarshal(raw, &test) != nil || test.ID == "" {
		t.Fatalf("POST /v1/tests (%s) as %s = %d: %s", kind, tn.slug, code, raw)
	}
	return test
}

// latest is the tenant's newest result per test, keyed by test id.
func (tn *synthTenant) latest(t *testing.T, st *shipped.Stack) map[string]synthResult {
	t.Helper()
	var out synthResults
	tn.get(t, st, "/v1/results/latest", &out)
	m := map[string]synthResult{}
	for _, r := range out.Items {
		if id := r.Attributes["probectl.test.id"]; id != "" {
			m[id] = r
		}
	}
	return m
}

func (tn *synthTenant) get(t *testing.T, st *shipped.Stack, path string, out any) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodGet, path, nil)
	if code != http.StatusOK || json.Unmarshal(raw, out) != nil {
		t.Fatalf("GET %s as %s = %d: %.300s", path, tn.slug, code, raw)
	}
}

func testIDs(tests []synthTest) map[string]bool {
	ids := map[string]bool{}
	for _, test := range tests {
		ids[test.ID] = true
	}
	return ids
}

// serveDNSAnswers is an authoritative DNS server on loopback UDP answering
// every A question with ip.
func serveDNSAnswers(t *testing.T, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// serveRTPEcho is a far end that echoes every RTP datagram back, as a voice
// test's responder does.
func serveRTPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

// laneCount counts the records on topic whose bus key names tenant.
func laneCount(t *testing.T, topic, tenant string) int {
	t.Helper()
	cl, err := kgo.NewClient(kgo.SeedBrokers(testsupport.KafkaBrokers()...), kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	n := 0
	deadline := time.Now().Add(20 * time.Second)
	for idle := 0; idle < 2 && time.Now().Before(deadline); {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		fetches := cl.PollFetches(ctx)
		cancel()
		got := 0
		fetches.EachRecord(func(r *kgo.Record) {
			got++
			if key := string(r.Key); key == tenant || strings.HasPrefix(key, tenant+"|") {
				n++
			}
		})
		if got == 0 {
			idle++
		} else {
			idle = 0
		}
	}
	return n
}

func promCount(t *testing.T, promql string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(os.Getenv("PROBECTL_PROM_URL"), "/")+"/api/v1/query?query="+url.QueryEscape(promql), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("query Prometheus: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode the Prometheus answer: %v", err)
	}
	if len(out.Data.Result) == 0 || len(out.Data.Result[0].Value) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(fmt.Sprint(out.Data.Result[0].Value[1]))
	return n
}
