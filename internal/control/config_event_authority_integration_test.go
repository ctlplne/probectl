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
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestConfigChangeEvidenceRechecksOriginalsCurrentContextAndCredential(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	ops := device.NewPostgresOpsStore(f.pool)
	f.server.WithDeviceOps(ops)
	f.server.cfg.AIPersistAnswers = true
	model := &pathHealthRCAModel{}
	f.server.analyzer = ai.NewAnalyzer(buildEngineWithPolicyLoader(f.server.cfg, f.pool, f.server.aiPolicyLoader(), f.server.aiSources()), ai.WithModel(model))
	originals := map[string]string{}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permChangeRead, permIncidentRead, ai.PermEventsRead, "ai.query"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		for _, value := range []string{"one", "two"} {
			cfg, err := ops.ArchiveConfig(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), device.ConfigVersion{TenantID: tenant, Device: "shared-name", Content: "hostname private-" + tenant + value, Binding: &device.ConfigArchiveBinding{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"}})
			if err != nil {
				t.Fatal(err)
			}
			originals[tenant] = cfg.ID
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	read := func(tenant string, ask bool) (int, string) {
		t.Helper()
		method, route := http.MethodGet, "/v1/changes"
		body := []byte{}
		if ask {
			method, route = http.MethodPost, "/v1/ai/ask"
			body = []byte(`{"question":"What changed?","subject":{"type":"change"}}`)
		}
		request, err := http.NewRequestWithContext(t.Context(), method, socket.URL+route, bytes.NewReader(body))
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
		encoded, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(encoded)
	}
	a, b := f.tenants[0], f.tenants[1]
	for _, tenant := range f.tenants {
		request := httptest.NewRequest(http.MethodGet, "/v1/changes", nil)
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		actor := f.server.resolvePrincipal(request)
		if actor == nil {
			t.Fatal("missing current report actor")
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			ctx, err := bindFlowRoleContext(ctx, actor)
			if err != nil {
				return err
			}
			capture, err := f.server.captureClientReportEventsInScope(ctx, sc, actor, time.Now().Add(-time.Hour), time.Now().Add(time.Minute), 256<<20)
			if err != nil {
				return err
			}
			if len(capture.Changes) != 1 || capture.Changes[0].Config == nil || capture.Changes[0].Config.CurrentID != originals[tenant] {
				t.Fatal("report changed original config identity")
			}
			return nil
		})
	}
	for _, tenant := range f.tenants {
		code, body := read(tenant, false)
		var response struct{ Items []json.RawMessage }
		if err := json.Unmarshal([]byte(body), &response); err != nil || code != http.StatusOK || len(response.Items) != 1 || !strings.Contains(body, originals[tenant]) || strings.Contains(body, "hostname private") {
			t.Fatal("owned config timeline lost original identity or included content", code, body, err)
		}
		if code, body := read(tenant, true); code != http.StatusOK {
			t.Fatal("owned config evidence could not reach stateless RCA", code, body)
		}
	}
	seedInterfaceRoleMCPConsent(f)
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleTLSCaller(t, f, wire, false)
		for _, tenant := range f.tenants {
			var answer ai.Answer
			call(tenant, "explain_degradation", map[string]any{"question": "What changed?", "subject": map[string]string{"type": "change"}}, &answer, true)
			if len(answer.Evidence) != 1 || answer.Evidence[0].Fields["ref"] != originals[tenant] {
				t.Fatal("native config evidence lost its exact original reference", wire, answer.Evidence)
			}
		}
	}
	// These are security controls: late permission/credential/erasure must
	// refuse publication, with the other tenant's exact source still usable.
	mutated := false
	model.after = func() {
		mutated = true
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='entities.read'`, a, f.roles[a])
			return err
		})
	}
	if code, body := read(a, true); code == http.StatusOK || strings.Contains(body, originals[a]) {
		t.Fatal("late context grant withdrawal published config evidence", code, body)
	}
	if !mutated {
		t.Fatal("late permission control did not reach model dispatch")
	}
	model.after = nil
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], "entities.read")
	})
	model.after = func() {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM device_configs WHERE tenant_id=$1 AND id=$2`, a, originals[a])
			return err
		})
	}
	if code, body := read(a, true); code == http.StatusOK || strings.Contains(body, originals[a]) {
		t.Fatal("late erased original was published as current config evidence", code, body)
	}
	model.after = nil
	if code, body := read(b, true); code != http.StatusOK {
		t.Fatal("source refusal damaged sibling evidence", code, body)
	}
	model.after = func() {
		f.in(b, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE mcp_tokens SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND user_id=$2`, b, f.users[b])
			return err
		})
	}
	if code, body := read(b, true); code == http.StatusOK || strings.Contains(body, originals[b]) {
		t.Fatal("late original credential revocation published config evidence", code, body)
	}
	model.after = nil
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var retained int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM ai_answers WHERE tenant_id=$1`, tenant).Scan(&retained); err != nil || retained != 0 {
				t.Fatal("live config evidence created private conversation history", retained, err)
			}
			return nil
		})
	}
}
