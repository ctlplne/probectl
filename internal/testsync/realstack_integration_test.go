// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package testsync_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/internal/testsync"
)

// TestCentralTestsReachAgentsRealStack is the real-stack receipt for central
// test distribution (beta gate G9, PLAT-13, docs/adr/central-test-distribution.md):
// a test a user creates in the rendered console, the CLI or the REST API
// reaches only its own tenant's agent, which verifies the signed bundle and
// runs it, for every isolation model: a pooled, a hybrid and a siloed tenant. It is also the canary
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
// Tenant A is pooled, B hybrid and C siloed (its control state in its own
// Postgres schema, provisioned by the shipped silo provisioner and routed by
// the installed tenancy router; its bus lane namespaced).
//
//  1. Every agent starts and applies its tenant's (empty) test set; each
//     tenant's `probectl isolation status` names its model's routing.
//  2. Tenant A's admin, signed in through the IdP in Chromium, creates an HTTP
//     test in the onboarding "Create the first test" form. Tenant B's admin
//     creates one with `probectl test create`, tenant C's with POST /v1/tests.
//  3. Each agent pulls, verifies and runs exactly its own tenant's test:
//     results for a tenant's test come from its agent and appear in that
//     tenant only; no other tenant's API, CLI or console holds them. The
//     namespaced tenants' results ride their own bus lane, never the shared
//     one, which carries the pooled tenant's; the result pipeline consuming
//     each lane writes the tenant's probe series to Prometheus, and the
//     tenant's own PromQL endpoint answers for its tests only.
//  4. Each agent's persisted bundle verifies against the deployment key,
//     names its own tenant and holds only that tenant's test.
//  5. GET /v1/agents and `probectl agent list` report each agent in sync, and
//     the rendered Admin agents table says "In sync" for the tenant's agent
//     only. /v1/me, `probectl me show` and the API docs page answer as the
//     caller (F10).
//  6. Storage placement, read with the privileged login RLS does not filter:
//     the siloed tenant's test, test-set version and agent (with the version
//     it applied) live in its own schema and nowhere in the shared one, and
//     its schema holds no other tenant's rows; the others' live in public.
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
	C := &g9Tenant{slug: "g9-initech-" + run, name: "Central Initech", model: "siloed", admin: "carla@acme.example"}
	tenants := []*g9Tenant{A, B, C}

	// 1. Agents with no local tests, enrolled while distribution is on.
	for i, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark = row.ID, fmt.Sprintf("g9%d-%s", i, run)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "test.read", "test.write", "test.allow_private", "agent.read")
		tn.readPosture(t, st)
		tn.agent = uuid(t)
		tn.agentName = "g9-agent-" + tn.id[:8]
		tn.identity = st.EnrollAgent(t, tn.id, tn.agent, tn.agentName)
		if _, err := os.Stat(filepath.Join(tn.identity, "testsync.pub")); err != nil {
			t.Fatalf("enrollment did not hand %s's agent the test-bundle key: %v", tn.slug, err)
		}
		tn.agentLog = st.StartAgent(t, tn.identity, tn.agentName, []string{"http"}, g9AgentTestSync)
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
	// Tenant C's test, through the REST API.
	C.testName = "g9 api " + C.mark
	C.target = page.URL(C.mark)
	code, raw := st.Do(t, C.cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": C.testName, "type": "http", "target": C.target, "interval_seconds": 10, "timeout_seconds": 5,
		"params": map[string]string{"allow_private_targets": "true"}, "enabled": true,
	})
	if code != http.StatusCreated || json.Unmarshal(raw, &created) != nil || created.ID == "" || created.ID == B.testID {
		t.Fatalf("POST /v1/tests as tenant C = %d: %s", code, raw)
	}
	C.testID = created.ID

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
	// PLAT-13: the API-created test runs within one interval of the agent
	// verifying and applying the bundle that carries it.
	checkFirstRunWithinInterval(t, st, C, 10*time.Second)
	for _, tn := range tenants {
		latest := tn.latest(t, st)
		var history g9Results
		tn.get(t, st, "/v1/results/history?window=1h", &history)
		for _, other := range tn.others(tenants) {
			if _, leaked := latest[other.testID]; leaked {
				t.Errorf("tenant %s's latest results hold %s's test %s", tn.slug, other.slug, other.testID)
			}
			foreign := 0
			for _, r := range history.Items {
				if r.Attributes["probectl.test.id"] == other.testID || r.AgentID == other.agent {
					foreign++
				}
			}
			if foreign > 0 {
				t.Errorf("tenant %s's result history holds %d results of %s's test or agent", tn.slug, foreign, other.slug)
			}
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
	// The bus: a namespaced tenant's results ride its own lane only; the
	// shared lane carries the pooled tenant's (so its zero is not vacuous).
	for _, tn := range tenants {
		shared := laneCount(t, "probectl.network.results", tn.id)
		t.Logf("tenant %s (%s): %d results on the shared lane", tn.slug, tn.model, shared)
		if tn.ns == "" {
			if shared == 0 {
				t.Errorf("no result of the pooled tenant %s on the shared lane probectl.network.results", tn.slug)
			}
			continue
		}
		if shared != 0 {
			t.Errorf("the %s tenant %s's results rode the shared lane (%d records)", tn.model, tn.slug, shared)
		}
		own := laneCount(t, "probectl."+tn.ns+".network.results", tn.id)
		t.Logf("tenant %s (%s): %d results on its lane probectl.%s.network.results", tn.slug, tn.model, own, tn.ns)
		if own == 0 {
			t.Errorf("no result of the %s tenant %s on its lane probectl.%s.network.results", tn.model, tn.slug, tn.ns)
		}
	}
	// The TSDB: the pipeline consuming each lane writes the tenant's probe
	// series, labeled with it; its PromQL endpoint answers for its own tests
	// and for no other tenant's (whose series exist, asserted in their turn).
	for _, tn := range tenants {
		if !eventually(90*time.Second, func() bool { return len(tn.series(t, st, tn.testID)) > 0 }) {
			t.Errorf("no probectl_probe_success series of %s's test %s through its PromQL endpoint within 90s", tn.slug, tn.testID)
			continue
		}
		own := tn.series(t, st, tn.testID)
		t.Logf("tenant %s (%s): %d probe series of its test in Prometheus", tn.slug, tn.model, len(own))
		for _, labels := range own {
			if labels["tenant_id"] != tn.id || labels["agent_id"] != tn.agent {
				t.Errorf("%s's probe series of its test carries %v, want its tenant %s and agent %s", tn.slug, labels, tn.id, tn.agent)
			}
		}
		for _, other := range tn.others(tenants) {
			if n := len(tn.series(t, st, other.testID)); n != 0 {
				t.Errorf("tenant %s's PromQL endpoint answers %d series of %s's test %s", tn.slug, n, other.slug, other.testID)
			}
		}
	}

	// 4. What each agent received: one verified bundle, its own tenant's.
	for _, tn := range tenants {
		b := tn.persistedBundle(t, st)
		if b.TenantID != tn.id {
			t.Errorf("agent %s holds a bundle for tenant %s, want its own %s", tn.agentName, b.TenantID, tn.id)
		}
		for _, test := range b.Tests {
			for _, other := range tn.others(tenants) {
				if test.ID == other.testID {
					t.Errorf("agent %s (tenant %s) received %s's test %s", tn.agentName, tn.slug, other.slug, other.testID)
				}
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
		admin.Absent = []string{"None applied", "Behind"}
		targets := console
		targets.URL = st.BaseURL + "/ui/targets"
		targets.Expect = []string{"Targets & Tests", tn.testName}
		for _, other := range tn.others(tenants) {
			admin.Absent = append(admin.Absent, other.agentName)
			targets.Absent = append(targets.Absent, other.testName, other.mark)
		}
		testsupport.RenderUI(t, admin)
		targets.Steps = []testsupport.RenderStep{
			{Click: "Results for " + tn.testName, Expect: []string{tn.testName + " — latest results", tn.agent, "ok"}},
		}
		testsupport.RenderUI(t, targets)
	}

	// 6. Where each tenant's test-distribution state physically lives.
	checkPlacement(t, st, tenants)
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/docs/api",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: B.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"API docs", "probectl control-plane API"},
	})

	// 7. A tampered bundle is refused end to end (PLAT-13 acceptance).
	checkTamperedBundleRefused(t, st, A, page, "g9tamper-"+run)

	// 8. A siloed tenant's record forged onto the SHARED lane is refused.
	checkSharedLaneRefusesSiloedTenant(t, st, C, "g9forged-"+run)
}

// checkSharedLaneRefusesSiloedTenant publishes, straight onto the shared
// network-results lane, a well-formed result keyed and stamped as the siloed
// tenant tn: what a misrouting control plane, a stale producer or a forger
// would put there. The router sends tn to its own lane, so every result
// consumer must refuse it: it never reaches tn's latest results or its probe
// series, and the control plane logs the refusal. The G9 siloed leg's plant 2
// showed such records were accepted under their tenant before.
func checkSharedLaneRefusesSiloedTenant(t *testing.T, st *shipped.Stack, tn *g9Tenant, forgedTest string) {
	t.Helper()
	if tn.ns == "" {
		t.Fatalf("tenant %s (%s) reports no own bus lane; the forged-record leg needs a siloed tenant", tn.slug, tn.model)
	}
	value, err := proto.Marshal(&resultv1.Result{
		TenantId: tn.id, AgentId: tn.agent, ResultId: forgedTest, CanaryType: "http",
		ServerAddress: "127.0.0.1", Success: true, StartTimeUnixNano: time.Now().UnixNano(),
		Metrics:    map[string]float64{"http.total.ms": 1},
		Attributes: map[string]string{"probectl.test.id": forgedTest},
	})
	if err != nil {
		t.Fatal(err)
	}
	cl, err := kgo.NewClient(kgo.SeedBrokers(testsupport.KafkaBrokers()...))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := range 5 {
		rec := &kgo.Record{Topic: "probectl.network.results", Key: bus.TenantKey(tn.id, fmt.Sprintf("forged-%d", i)), Value: value}
		if err := cl.ProduceSync(ctx, rec).FirstErr(); err != nil {
			t.Fatalf("publish the forged result on the shared lane: %v", err)
		}
	}
	refused := func() bool {
		out, _ := os.ReadFile(st.Log)
		return strings.Contains(string(out), "its tenant is routed to its own bus lane but it arrived on the shared lane") &&
			strings.Contains(string(out), tn.id)
	}
	accepted := func() bool { _, seen := tn.latest(t, st)[forgedTest]; return seen }
	shipped.Await(t, "the control plane refusing (or, if broken, accepting) "+tn.slug+"'s records on the shared lane", 30*time.Second, func() bool {
		return refused() || accepted()
	})
	time.Sleep(5 * time.Second) // every consumer group has read the lane by now
	if accepted() {
		t.Errorf("ISOLATION: a result forged onto the shared lane as siloed tenant %s reached its latest results", tn.slug)
	}
	if !refused() {
		t.Errorf("ISOLATION: the control plane did not refuse %s's results on the shared lane", tn.slug)
	}
	if n := len(tn.series(t, st, forgedTest)); n != 0 {
		t.Errorf("ISOLATION: a result forged onto the shared lane as siloed tenant %s became %d probe series", tn.slug, n)
	}
	t.Logf("5 results forged onto the shared lane as siloed tenant %s were refused: none in its latest results or probe series", tn.slug)
}

// checkFirstRunWithinInterval measures PLAT-13's "executed by an enrolled
// agent within one interval after the agent verifies the signed bundle": the
// agent's own log names when it verified and applied the bundle that carries
// tn's test (only a verified bundle is ever applied), and the earliest result
// of that test in the tenant's history must be observed within one interval
// of it.
func checkFirstRunWithinInterval(t *testing.T, st *shipped.Stack, tn *g9Tenant, interval time.Duration) {
	t.Helper()
	epoch := tn.persistedBundle(t, st).Epoch
	applied, ok := appliedAt(t, tn.agentLog, epoch)
	if !ok {
		t.Fatalf("agent %s logged no \"applied central test set\" for v%d", tn.agentName, epoch)
	}
	var history g9Results
	tn.get(t, st, "/v1/results/history?window=1h", &history)
	var first time.Time
	for _, r := range history.Items {
		if r.Attributes["probectl.test.id"] == tn.testID && (first.IsZero() || r.ObservedAt.Before(first)) {
			first = r.ObservedAt
		}
	}
	if first.IsZero() {
		t.Fatalf("tenant %s's result history holds no result of its test %s", tn.slug, tn.testID)
	}
	lag := first.Sub(applied)
	t.Logf("agent %s applied v%d at %s; first result of %s's API-created test observed %s later (interval %s)",
		tn.agentName, epoch, applied.Format(time.RFC3339Nano), tn.slug, lag, interval)
	if lag < -time.Second || lag > interval {
		t.Errorf("PLAT-13: %s's API-created test first ran %s after its agent applied the verified bundle, want within one interval (%s)",
			tn.slug, lag, interval)
	}
}

// appliedAt is when the agent logged applying the central test set at
// version epoch (the agent logs JSON by default).
func appliedAt(t *testing.T, logPath string, epoch int64) (time.Time, bool) {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		var rec struct {
			Time    time.Time `json:"time"`
			Msg     string    `json:"msg"`
			Version int64     `json:"version"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "test sync: applied central test set" && rec.Version == epoch {
			return rec.Time, true
		}
	}
	return time.Time{}, false
}

// g9AgentTestSync is each agent's test_sync block: no local tests, central
// tests on, and private targets allowed because the target is a loopback
// page the operator owns.
const g9AgentTestSync = `test_sync:
  enabled: true
  interval: 2s
  allowed_types: [http]
  allow_private_targets: true
`

// checkTamperedBundleRefused stops tn's agent, rewrites the signed bundle it
// persisted so its test probes a different page under the original
// signature, and restarts the shipped agent. The agent must refuse the
// tampered bundle at start, fetch and verify the control plane's bundle
// again, and go on running only the verified test: the tampered target is
// never probed, the real one is.
func checkTamperedBundleRefused(t *testing.T, st *shipped.Stack, tn *g9Tenant, page *markedPage, tamperMark string) {
	t.Helper()
	legit := tn.persistedBundle(t, st)
	st.Stop(t, "agent-"+tn.agentName)
	path := filepath.Join(st.Dir, "buffer-"+tn.agentName, "testsync", "bundle.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var signed testsync.Signed
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	var b testsync.Bundle
	if err := json.Unmarshal(signed.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Tests) != 1 {
		t.Fatalf("agent %s persisted %d tests, want its one", tn.agentName, len(b.Tests))
	}
	b.Tests[0].Target = page.URL(tamperMark) // the same signature now covers different bytes
	if signed.Bundle, err = json.Marshal(b); err != nil {
		t.Fatal(err)
	}
	if raw, err = json.Marshal(signed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	before := page.hits(tn.mark)
	logPath := st.StartAgent(t, tn.identity, tn.agentName, []string{"http"}, g9AgentTestSync)
	refused := func() bool {
		out, _ := os.ReadFile(logPath)
		return strings.Contains(string(out), "persisted bundle refused")
	}
	shipped.Await(t, tn.agentName+" refusing (or, if broken, running) its tampered persisted bundle", 30*time.Second, func() bool {
		return refused() || page.hits(tamperMark) > 0
	})
	if n := page.hits(tamperMark); n != 0 || !refused() {
		t.Fatalf("TAMPER ACCEPTED: agent %s did not refuse its tampered persisted bundle (refusal logged: %t) and probed the tampered target %d times",
			tn.agentName, refused(), n)
	}
	shipped.Await(t, tn.agentName+" back in sync on the verified bundle", 60*time.Second, func() bool {
		ts := tn.agentTestSet(t, st)
		return ts != nil && ts.InSync && ts.AppliedVersion == uint64(legit.Epoch)
	})
	shipped.Await(t, tn.agentName+" probing its verified target again", 60*time.Second, func() bool {
		return page.hits(tn.mark) > before
	})
	if again := tn.persistedBundle(t, st); len(again.Tests) != 1 || again.Tests[0].Target != tn.target {
		t.Errorf("agent %s re-persisted %+v, want the verified bundle's test on %s", tn.agentName, again.Tests, tn.target)
	}
	if n := page.hits(tamperMark); n != 0 {
		t.Errorf("TAMPER ACCEPTED: agent %s probed the tampered bundle's target %d times", tn.agentName, n)
	}
	t.Logf("agent %s refused its tampered persisted bundle, re-synced to v%d and probes only %s (tampered target hit %d times)",
		tn.agentName, legit.Epoch, tn.target, page.hits(tamperMark))
}

type g9Tenant struct {
	slug, name, model, admin       string
	id, mark, cookie, token, agent string
	agentName, identity, agentLog  string
	testName, testID, target       string
	ns, pgSchema                   string // the routing `probectl isolation status` reports
}

type g9TestSet struct {
	AppliedVersion uint64 `json:"applied_version"`
	CurrentVersion uint64 `json:"current_version"`
	InSync         bool   `json:"in_sync"`
}

type g9Result struct {
	AgentID    string             `json:"agent_id"`
	ObservedAt time.Time          `json:"observed_at"`
	Success    bool               `json:"success"`
	Metrics    map[string]float64 `json:"metrics"`
	Attributes map[string]string  `json:"attributes"`
}

type g9Results struct {
	Items []g9Result `json:"items"`
}

// others is every tenant of the receipt but tn.
func (tn *g9Tenant) others(all []*g9Tenant) []*g9Tenant {
	out := make([]*g9Tenant, 0, len(all)-1)
	for _, o := range all {
		if o != tn {
			out = append(out, o)
		}
	}
	return out
}

// readPosture records the tenant's routing from `probectl isolation status`
// and fails unless it is its model's: a siloed tenant has its own Postgres
// schema and bus lane, a hybrid one a lane only, a pooled one neither.
func (tn *g9Tenant) readPosture(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var posture struct {
		EffectiveModel string `json:"effective_model"`
		LaneNamespace  struct {
			Namespace string `json:"namespace"`
		} `json:"lane_namespace"`
		SiloRouting struct {
			Resolved bool   `json:"resolved"`
			PGSchema string `json:"pg_schema"`
		} `json:"silo_routing"`
	}
	st.MustCLI(t, tn.env(), &posture, "isolation", "status")
	tn.ns, tn.pgSchema = posture.LaneNamespace.Namespace, posture.SiloRouting.PGSchema
	t.Logf("tenant %s (%s): postgres schema %q, bus lane namespace %q", tn.slug, posture.EffectiveModel, tn.pgSchema, tn.ns)
	wantSchema, wantLane := tn.model == "siloed", tn.model != "pooled"
	if posture.EffectiveModel != tn.model || !posture.SiloRouting.Resolved ||
		(tn.pgSchema != "") != wantSchema || (tn.ns != "") != wantLane {
		t.Fatalf("probectl isolation status as %s (%s) = %+v", tn.slug, tn.model, posture)
	}
}

// g9Rows is one table's rows for a tenant, read with the privileged login.
type g9Rows struct {
	Own     []string // the tenant's rows in the schema its model routes to
	Public  int      // a siloed tenant's rows in the shared public schema
	Foreign int      // other tenants' rows in a siloed tenant's own schema
}

// placementTables are the tenant-owned tables central test distribution
// writes, each with the expression that identifies a row in the receipt.
var placementTables = map[string]string{
	"tests":                    "id::text",
	"tenant_test_set_versions": "version::text",
	"agents":                   "id::text || '@' || COALESCE(test_set_version, 0)::text",
}

// checkPlacement reads where each tenant's tests, test-set version and agent
// physically live, with the privileged login (a superuser, which RLS does not
// filter), so the siloed tenant's isolation is shown at the storage layer and
// not only through its own scoped reads: a siloed tenant routed to the shared
// schema would still read its own rows back through RLS.
func checkPlacement(t *testing.T, st *shipped.Stack, tenants []*g9Tenant) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, tn := range tenants {
		epoch := strconv.FormatInt(tn.persistedBundle(t, st).Epoch, 10)
		want := map[string]string{"tests": tn.testID, "tenant_test_set_versions": epoch, "agents": tn.agent + "@" + epoch}
		for table, expr := range placementTables {
			got := tn.rows(ctx, t, pool, table, expr)
			if tn.pgSchema != "" {
				t.Logf("%s (%s): %s.%s = %v; its rows in public.%s %d, other tenants' rows in its schema %d",
					tn.slug, tn.model, tn.schema(), table, got.Own, table, got.Public, got.Foreign)
			} else {
				t.Logf("%s (%s): %s.%s = %v", tn.slug, tn.model, tn.schema(), table, got.Own)
			}
			if len(got.Own) != 1 || got.Own[0] != want[table] {
				t.Errorf("%s's rows in %s.%s = %v, want exactly [%s]", tn.slug, tn.schema(), table, got.Own, want[table])
			}
			if got.Public != 0 {
				t.Errorf("ISOLATION: the siloed tenant %s has %d rows in the shared public.%s", tn.slug, got.Public, table)
			}
			if got.Foreign != 0 {
				t.Errorf("ISOLATION: %s's silo schema %s.%s holds %d rows of other tenants", tn.slug, tn.pgSchema, table, got.Foreign)
			}
		}
	}
}

// schema is the Postgres schema the tenant's control state is routed to.
func (tn *g9Tenant) schema() string {
	if tn.pgSchema != "" {
		return tn.pgSchema
	}
	return "public"
}

// rows reads one table's rows of the tenant in the schema its model routes
// to and, for a siloed tenant, counts its rows in public and other tenants'
// rows in its own schema.
func (tn *g9Tenant) rows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, table, expr string) g9Rows {
	t.Helper()
	count := func(schema, op string) int {
		var n int
		q := `SELECT count(*) FROM ` + pgx.Identifier{schema, table}.Sanitize() + ` WHERE tenant_id ` + op + ` $1::uuid`
		if err := pool.QueryRow(ctx, q, tn.id).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	var out g9Rows
	q := `SELECT ` + expr + ` FROM ` + pgx.Identifier{tn.schema(), table}.Sanitize() + ` WHERE tenant_id = $1::uuid ORDER BY 1`
	rows, err := pool.Query(ctx, q, tn.id)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out.Own = append(out.Own, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	if tn.pgSchema != "" {
		out.Public, out.Foreign = count("public", "="), count(tn.pgSchema, "<>")
	}
	return out
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

// series is the label sets of the probectl_probe_success series of testID
// that the tenant's own PromQL endpoint (the Grafana datasource) answers.
func (tn *g9Tenant) series(t *testing.T, st *shipped.Stack, testID string) []map[string]string {
	t.Helper()
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
			} `json:"result"`
		} `json:"data"`
	}
	tn.get(t, st, "/v1/grafana/api/v1/query?query="+url.QueryEscape(`probectl_probe_success{test_id="`+testID+`"}`), &out)
	labels := make([]map[string]string, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		labels = append(labels, r.Metric)
	}
	return labels
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
