// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type pathHealthRCAModel struct {
	calls int
	after func()
}

func (*pathHealthRCAModel) Name() string { return "builtin-path-proof" }
func (model *pathHealthRCAModel) Synthesize(ctx context.Context, input ai.SynthesisInput) (ai.Synthesis, error) {
	model.calls++
	if model.after != nil {
		model.after()
	}
	return ai.NewBuiltinModel().Synthesize(ctx, input)
}

func TestPathHealthRCAUsesCompleteCurrentOwnedSnapshot(t *testing.T) {
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	f.server.cfg.AIPersistAnswers = true
	policy := fairness.DefaultPolicy()
	policy.QueryConcurrency = 1
	f.server.WithFairness(fairness.NewGate(policy, nil))
	model := &pathHealthRCAModel{}
	f.server.analyzer = ai.NewAnalyzer(buildEngineWithPolicyLoader(f.server.cfg, f.pool, f.server.aiPolicyLoader(), f.server.aiSources()), ai.WithMaxEvidence(1), ai.WithModel(model))
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "ai.query")
		})
		var hops []path.Hop
		address := netip.MustParseAddr("203.0.113.1")
		for i := range 500 {
			hops = append(hops, path.Hop{TTL: i + 1, Nodes: []path.HopNode{{IP: address.String()}}})
			address = address.Next()
		}
		hops = append(hops, path.Hop{TTL: 501, Nodes: []path.HopNode{{IP: "10.42.0.2"}}})
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := f.server.pathStore.Save(pathstore.WithDiscoveryStartedAt(ctx, f.observedAt(tenant)), tenant, &path.Path{Target: "198.51.100.10", Hops: hops}); err != nil {
			t.Fatal(err)
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	call := func(tenant, test string) (int, []byte) {
		t.Helper()
		params := proof.windows[tenant]
		payload := map[string]any{"question": "Explain observed path errors and utilization; do not claim causation without evidence.", "subject": map[string]string{"path_test_id": test, "target": "198.51.100.10", "health_poll_gap": params.Get("health_poll_gap"), "health_max_bps": params.Get("health_max_bps")}, "range": map[string]string{"start": params.Get("health_from"), "end": params.Get("health_to")}}
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/ai/ask", bytes.NewReader(body))
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
	read := func(lane int) {
		t.Helper()
		tenant := f.tenants[lane]
		code, raw := call(tenant, proof.tests[tenant])
		if code != http.StatusOK {
			t.Fatal("owned path RCA refused its admitted complete snapshot", code, string(raw))
		}
		var answer ai.Answer
		if err := json.Unmarshal(raw, &answer); err != nil {
			t.Fatal(err)
		}
		if answer.Tenant != tenant || len(answer.Evidence) != 1 || len(answer.RootCauseCitations) == 0 || !answer.RootCauseGrounded || answer.Evidence[0].Fields["path_health"] == nil {
			t.Fatal("owned complete path evidence was not cited")
		}
		pack, err := json.Marshal(answer.Evidence[0].Fields["path_health"])
		if err != nil {
			t.Fatal(err)
		}
		var health pathHealthResult
		if err := json.Unmarshal(pack, &health); err != nil {
			t.Fatal(err)
		}
		if health.TestID != proof.tests[tenant] || len(health.Items) != 501 || health.Items[0].Health == nil || health.Items[0].Health.Status != "identity_unresolved" || health.Items[500].Health == nil || len(health.Items[500].Health.Counters) != len(pathHealthMetricNames) {
			t.Fatal("RCA shortened the complete path or lost the late polled hop")
		}
		counter := health.Items[500].Health.Counters[0]
		if counter.PreviousValue != "9007199254740993" || counter.UtilizationNumerator != "98" || counter.UtilizationDenominator != "1" || counter.CaptureKey == "" || health.Items[500].Health.Counters[2].MinimumDelta == "0" {
			t.Fatal("RCA changed exact late-hop observations or their original receipts")
		}
		if counter.PollCompletedAt == nil || !answer.Evidence[0].OccurredAt.Equal(*counter.PollCompletedAt) {
			t.Fatal("RCA replaced the original observation clock with its query window")
		}
		if answer.RootCauseCitations[0].EvidenceID != answer.Evidence[0].ID || !strings.Contains(answer.Evidence[0].Summary, "501") || strings.Contains(string(raw), f.tenants[1-lane]) {
			t.Fatal("RCA cited a different source or crossed the tenant boundary")
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			exists, err := (store.AIAnswers{}).Exists(ctx, sc, answer.ID)
			if err == nil && exists {
				t.Fatal("live path evidence was retained as an answer artifact")
			}
			return err
		})
	}
	read(0)
	read(1)
	a, b := f.tenants[0], f.tenants[1]
	before := model.calls
	if code, raw := call(a, ""); code != http.StatusUnprocessableEntity || strings.Contains(string(raw), "capture_key") || model.calls != before {
		t.Fatal("empty explicit path ID fell back to unrelated evidence", code)
	}
	if code, raw := call(a, proof.tests[b]); code == http.StatusOK || strings.Contains(string(raw), "capture_key") || model.calls != before {
		t.Fatal("foreign path ID broadened RCA into unrelated evidence", code)
	}
	// Revocation during synthesis must prevent the complete answer from being
	// published, and must not invalidate the sibling's source or cached result.
	for _, permission := range []string{"metrics.read", "ai.query"} {
		model.after = func() {
			model.after = nil
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
				return err
			})
		}
		if code, raw := call(a, proof.tests[a]); code == http.StatusOK || strings.Contains(string(raw), "capture_key") {
			t.Fatal("changed current authority published a path RCA answer", permission, code)
		}
		read(1)
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
		})
	}
	t.Log("real-integration: verified TLS/RLS and current role/sibling publication, full501-hop evidence despite one evidence slot; modeled path, counters, clocks and source receipts, no physical FRR/SNMP/RCA proof")
}
