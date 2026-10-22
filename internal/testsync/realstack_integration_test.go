// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package testsync_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/internal/testsync"
)

// TestCentralTestsReachAgentsRealStack is the real-stack receipt for central
// test distribution (beta gate G9, PLAT-13, docs/adr/central-test-distribution.md):
// a test a user creates in the rendered console reaches only its own tenant's
// agent, which verifies the signed bundle and runs it. It is also the canary
// agent's (F1) and the control plane's REST/gRPC/CLI (F10) receipt, now that
// the agent takes its tests from the control plane.
//
// The stack is the shipped control plane and agent on the full four-store
// profile (shipped.Start): PostgreSQL behind the least-privilege serve login,
// Kafka with strict tenant lanes, ClickHouse, Prometheus, TLS everywhere, the
// real IdP (production session auth, no dev auth) and an MSP license, plus a
// test-bundle signing key, so enrollment hands each agent the public half
// (testsync.pub). Each tenant's agent is enrolled over mTLS with a one-time
// join token and starts with NO local canaries; its own configuration allows
// central tests to probe private targets, because the target is a loopback
// page (the operator owns both ends).
//
//  1. Both agents start and apply their tenant's (empty) test set.
//  2. Tenant A's admin, signed in through the IdP in Chromium, creates an HTTP
//     test in the onboarding "Create the first test" form. Tenant B's admin
//     creates one with `probectl test create`.
//  3. Each agent pulls, verifies and runs exactly its own tenant's test:
//     results for A's test come from agent A and appear in tenant A only;
//     tenant B's API, CLI and console hold none of A's tests or results.
//  4. Each agent's persisted bundle verifies against the deployment key,
//     names its own tenant and holds only that tenant's test: agent B never
//     received A's test, nor agent A B's.
//  5. GET /v1/agents and `probectl agent list` report each agent in sync, and
//     the rendered Admin agents table says "In sync" for the tenant's agent
//     only. /v1/me, `probectl me show` and the API docs page answer as the
//     caller (F10).
func TestCentralTestsReachAgentsRealStack(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "testsync", TenantBand: 4, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "testsync-signing-key.pem"),
	}})
	op := st.OnboardOperator(t, "root@msp-testsync.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	page := newMarkedPage(t)

	A := &g9Tenant{slug: "g9-acme-" + run, name: "Central Acme", model: "pooled", admin: "ada@acme.example"}
	B := &g9Tenant{slug: "g9-globex-" + run, name: "Central Globex", model: "hybrid", admin: "bob@globex.example"}
	tenants := []*g9Tenant{A, B}

	// 1. Agents with no local tests, enrolled while distribution is on.
	for i, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark = row.ID, fmt.Sprintf("g9%d-%s", i, run)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "test.read", "test.write", "test.allow_private", "agent.read")
		tn.agent = uuid(t)
		tn.agentName = "g9-agent-" + tn.id[:8]
		tn.identity = st.EnrollAgent(t, tn.id, tn.agent, tn.agentName)
		if _, err := os.Stat(filepath.Join(tn.identity, "testsync.pub")); err != nil {
			t.Fatalf("enrollment did not hand %s's agent the test-bundle key: %v", tn.slug, err)
		}
		st.StartAgent(t, tn.identity, tn.agentName, []string{"http"}, `test_sync:
  enabled: true
  interval: 2s
  allowed_types: [http]
  allow_private_targets: true
`)
	}
	for _, tn := range tenants {
		shipped.Await(t, tn.slug+"'s agent applying its tenant's test set", 90*time.Second, func() bool {
			ts := tn.agentTestSet(t, st)
			return ts != nil && ts.InSync && ts.AppliedVersion > 0
		})
	}

	// 2. Tenant A's test, created in the rendered console's onboarding form.
	A.testName = "g9 ui " + A.mark
	A.target = page.URL(A.mark)
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/onboarding",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: A.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Create the first test"},
		Steps: []testsupport.RenderStep{
			{Fill: `label:text-is("Test name") + div input`, Value: A.testName},
			// Choosing a type resets the private-target exception, so the box
			// is ticked after it.
			{Select: `select:has(option[value="http"])`, Value: "http"},
			{Fill: `label:text-is("Target") + div input`, Value: A.target},
			{Fill: `label:text-is("Interval seconds") + div input`, Value: "10"},
			{Click: "Allow this test to probe private or loopback addresses", Role: "checkbox"},
			{Click: "Create first test", Expect: []string{A.testName + " is enabled"}},
		},
	})
	A.testID = A.findTest(t, st, A.testName)
	// Tenant B's test, through the CLI.
	B.testName = "g9 cli " + B.mark
	B.target = page.URL(B.mark)
	var created struct{ ID string }
	st.MustCLI(t, B.env(), &created, "test", "create", "--name", B.testName, "--type", "http",
		"--target", B.target, "--interval", "10", "--timeout", "5", "--param", "allow_private_targets=true")
	B.testID = created.ID
	if B.testID == "" {
		t.Fatal("probectl test create as tenant B returned no id")
	}

	// 3. Each agent runs its own tenant's test; results stay in their tenant.
	// A missing result is reported, not fatal, so the cross-tenant checks
	// below still name a test that reached the wrong agent.
	for _, tn := range tenants {
		if !eventually(120*time.Second, func() bool {
			r, ok := tn.latest(t, st)[tn.testID]
			return ok && r.Success
		}) {
			t.Errorf("no successful result of %s's central test %s within 2m", tn.slug, tn.testID)
			continue
		}
		if r := tn.latest(t, st)[tn.testID]; r.AgentID != tn.agent || r.Metrics["http.status"] != 200 {
			t.Errorf("%s's central test result = %+v, want HTTP 200 from its agent %s", tn.slug, r, tn.agent)
		}
		if page.hits(tn.mark) == 0 {
			t.Errorf("the target never saw %s's test (mark %s)", tn.slug, tn.mark)
		}
	}
	for _, tn := range tenants {
		other := tn.other(A, B)
		latest := tn.latest(t, st)
		if _, leaked := latest[other.testID]; leaked {
			t.Errorf("tenant %s's latest results hold %s's test %s", tn.slug, other.slug, other.testID)
		}
		var history g9Results
		tn.get(t, st, "/v1/results/history?window=1h", &history)
		foreign := 0
		for _, r := range history.Items {
			if r.Attributes["probectl.test.id"] == other.testID || r.AgentID == other.agent {
				foreign++
			}
		}
		if foreign > 0 {
			t.Errorf("tenant %s's result history holds %d results of %s's test or agent", tn.slug, foreign, other.slug)
		}
		var tests struct{ Items []struct{ ID, Name string } }
		tn.get(t, st, "/v1/tests", &tests)
		if len(tests.Items) != 1 || tests.Items[0].ID != tn.testID {
			t.Errorf("GET /v1/tests as %s = %+v, want only its test %s", tn.slug, tests.Items, tn.testID)
		}
		var cliTests []struct{ ID string }
		st.MustCLI(t, tn.env(), &cliTests, "test", "list")
		if len(cliTests) != 1 || cliTests[0].ID != tn.testID {
			t.Errorf("probectl test list as %s = %+v, want only its test %s", tn.slug, cliTests, tn.testID)
		}
	}

	// 4. What each agent received: one verified bundle, its own tenant's.
	for _, tn := range tenants {
		other := tn.other(A, B)
		b := tn.persistedBundle(t, st)
		if b.TenantID != tn.id {
			t.Errorf("agent %s holds a bundle for tenant %s, want its own %s", tn.agentName, b.TenantID, tn.id)
		}
		for _, test := range b.Tests {
			if test.ID == other.testID {
				t.Errorf("agent %s (tenant %s) received %s's test %s", tn.agentName, tn.slug, other.slug, other.testID)
			}
		}
		if len(b.Tests) != 1 || b.Tests[0].ID != tn.testID || b.Tests[0].Target != tn.target {
			t.Errorf("agent %s's bundle = %+v, want exactly %s's test %s", tn.agentName, b.Tests, tn.slug, tn.testID)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	// 5. The fleet view, the CLI and the console, per tenant.
	for _, tn := range tenants {
		other := tn.other(A, B)
		var ts *g9TestSet
		shipped.Await(t, tn.slug+"'s agent in sync with the new test set", 60*time.Second, func() bool {
			ts = tn.agentTestSet(t, st)
			return ts != nil && ts.InSync && ts.AppliedVersion == uint64(tn.persistedBundle(t, st).Epoch)
		})
		var cliAgents []struct {
			ID      string
			TestSet *g9TestSet `json:"test_set"`
		}
		st.MustCLI(t, tn.env(), &cliAgents, "agent", "list")
		if len(cliAgents) != 1 || cliAgents[0].ID != tn.agent || cliAgents[0].TestSet == nil || !cliAgents[0].TestSet.InSync {
			t.Errorf("probectl agent list as %s = %+v, want only its agent, in sync", tn.slug, cliAgents)
		}
		var me struct {
			TenantID string `json:"tenant_id"`
		}
		st.MustCLI(t, tn.env(), &me, "me", "show")
		var apiMe struct {
			TenantID string `json:"tenant_id"`
			Email    string `json:"email"`
		}
		tn.get(t, st, "/v1/me", &apiMe)
		if me.TenantID != tn.id || apiMe.TenantID != tn.id || apiMe.Email != tn.admin {
			t.Errorf("probectl me show / GET /v1/me as %s = %+v / %+v", tn.slug, me, apiMe)
		}

		console := testsupport.RenderSpec{
			Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
			TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		}
		admin := console
		admin.URL = st.BaseURL + "/ui/admin"
		admin.Expect = []string{tn.agentName, "In sync",
			fmt.Sprintf("Running v%d of v%d", ts.AppliedVersion, ts.CurrentVersion)}
		admin.Absent = []string{other.agentName, "None applied", "Behind"}
		testsupport.RenderUI(t, admin)
		targets := console
		targets.URL = st.BaseURL + "/ui/targets"
		targets.Expect = []string{"Targets & Tests", tn.testName}
		targets.Absent = []string{other.testName, other.mark}
		targets.Steps = []testsupport.RenderStep{
			{Click: "Results for " + tn.testName, Expect: []string{tn.testName + " — latest results", tn.agent, "ok"}},
		}
		testsupport.RenderUI(t, targets)
	}
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/docs/api",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: B.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"API docs", "probectl control-plane API"},
	})
}

type g9Tenant struct {
	slug, name, model, admin       string
	id, mark, cookie, token, agent string
	agentName, identity            string
	testName, testID, target       string
}

type g9TestSet struct {
	AppliedVersion uint64 `json:"applied_version"`
	CurrentVersion uint64 `json:"current_version"`
	InSync         bool   `json:"in_sync"`
}

type g9Result struct {
	AgentID    string             `json:"agent_id"`
	Success    bool               `json:"success"`
	Metrics    map[string]float64 `json:"metrics"`
	Attributes map[string]string  `json:"attributes"`
}

type g9Results struct {
	Items []g9Result `json:"items"`
}

func (tn *g9Tenant) other(a, b *g9Tenant) *g9Tenant {
	if tn == a {
		return b
	}
	return a
}

func (tn *g9Tenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

func (tn *g9Tenant) get(t *testing.T, st *shipped.Stack, path string, out any) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodGet, path, nil)
	if code != http.StatusOK || json.Unmarshal(raw, out) != nil {
		t.Fatalf("GET %s as %s = %d: %.300s", path, tn.slug, code, raw)
	}
}

// latest is the tenant's newest result per test, keyed by test id.
func (tn *g9Tenant) latest(t *testing.T, st *shipped.Stack) map[string]g9Result {
	t.Helper()
	var out g9Results
	tn.get(t, st, "/v1/results/latest", &out)
	m := map[string]g9Result{}
	for _, r := range out.Items {
		if id := r.Attributes["probectl.test.id"]; id != "" {
			m[id] = r
		}
	}
	return m
}

// findTest is the id of the tenant's test with that name.
func (tn *g9Tenant) findTest(t *testing.T, st *shipped.Stack, name string) string {
	t.Helper()
	var tests struct{ Items []struct{ ID, Name string } }
	tn.get(t, st, "/v1/tests", &tests)
	for _, test := range tests.Items {
		if test.Name == name {
			return test.ID
		}
	}
	t.Fatalf("tenant %s has no test named %q after the console created it: %+v", tn.slug, name, tests.Items)
	return ""
}

// agentTestSet is GET /v1/agents' test_set for the tenant's one agent (nil if
// the agent is not listed yet or carries none).
func (tn *g9Tenant) agentTestSet(t *testing.T, st *shipped.Stack) *g9TestSet {
	t.Helper()
	var agents struct {
		Items []struct {
			ID      string     `json:"id"`
			TestSet *g9TestSet `json:"test_set"`
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

// persistedBundle is the bundle the agent verified and saved
// (<buffer.dir>/testsync/bundle.json), verified again here against the
// deployment key enrollment gave the agent.
func (tn *g9Tenant) persistedBundle(t *testing.T, st *shipped.Stack) *testsync.Bundle {
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

// eventually polls fn until it holds or within elapses.
func eventually(within time.Duration, fn func() bool) bool {
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

// markedPage is the loopback HTTP target; it counts requests per tenant mark.
type markedPage struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen map[string]int
}

func newMarkedPage(t *testing.T) *markedPage {
	t.Helper()
	p := &markedPage{seen: map[string]int{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mark := r.URL.Query().Get("for")
		p.mu.Lock()
		p.seen[mark]++
		p.mu.Unlock()
		_, _ = io.WriteString(w, "central test ok for "+mark)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *markedPage) URL(mark string) string {
	return p.srv.URL + "/health?for=" + strings.TrimSpace(mark)
}

func (p *markedPage) hits(mark string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen[mark]
}
