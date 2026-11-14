// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestPathHealthConfigurationReferencesKeepCompleteOriginalScopeAndCitations(t *testing.T) {
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	ops := device.NewPostgresOpsStore(f.pool)
	f.server.WithDeviceOps(ops)
	model := &pathHealthRCAModel{}
	f.server.analyzer = ai.NewAnalyzer(buildEngineWithPolicyLoader(f.server.cfg, f.pool, f.server.aiPolicyLoader(), f.server.aiSources()), ai.WithModel(model), ai.WithMaxEvidence(1))
	originals := map[string][]device.ConfigVersion{}
	var latest time.Time
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "ai.query")
		})
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for i := range 2 {
			if _, err := ops.ArchiveConfig(ctx, device.ConfigVersion{TenantID: tenant, Device: "same-name", Content: fmt.Sprintf("LEGACY_MUST_NOT_ATTACH %d", i)}); err != nil {
				t.Fatal(err)
			}
		}
		for i := range 501 {
			row, err := ops.ArchiveConfig(ctx, device.ConfigVersion{TenantID: tenant, Device: fmt.Sprintf("display-name-%d", i%2), Source: "operator-fixture", Content: fmt.Sprintf("hostname original-%s\n description revision %d", tenant, i), Binding: &device.ConfigArchiveBinding{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"}})
			if err != nil {
				t.Fatal(err)
			}
			originals[tenant] = append(originals[tenant], row)
			if row.ObservedAt.After(latest) {
				latest = row.ObservedAt
			}
		}
	}
	if wait := time.Until(latest); wait > 0 {
		if wait > 5*time.Second {
			t.Fatal("fixture source clock exceeds skew allowance")
		}
		time.Sleep(wait)
	}
	for _, tenant := range f.tenants {
		proof.windows[tenant].Set("health_to", time.Now().UTC().Format(time.RFC3339Nano))
		proof.windows[tenant].Set("health_poll_gap", "2m")
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			from, err := time.Parse(time.RFC3339Nano, proof.windows[tenant].Get("health_from"))
			if err != nil {
				return err
			}
			to, err := time.Parse(time.RFC3339Nano, proof.windows[tenant].Get("health_to"))
			if err != nil {
				return err
			}
			events, err := (store.ChangeEvents{}).ClientReportConfigChangesInScope(ctx, sc, from, to, 64<<20)
			if err != nil {
				return err
			}
			count := 0
			for _, event := range events {
				if event.Config != nil && event.Config.Binding != nil {
					ref := event.Config
					count++
					if ref.CurrentVersion < 2 || ref.CurrentVersion > 501 || ref.CurrentID != originals[tenant][ref.CurrentVersion-1].ID || ref.PreviousID != originals[tenant][ref.CurrentVersion-2].ID || ref.Binding.ContextID != f.contextID || ref.Binding.DeviceEntityID != f.routerID {
						t.Fatal("monthly config projection crossed original canonical source streams")
					}
				}
			}
			if count != 500 {
				t.Fatal("monthly config projection lost complete canonical drifts", count)
			}
			return nil
		})
		if values := projectConfigChanges(originals[tenant], tenant); len(values) != 500 || values[0].Config == nil || values[0].Config.Binding == nil {
			t.Fatal("change projection did not retain the complete renamed canonical stream", len(values))
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	check := func(tenant string, value pathHealthResult) {
		t.Helper()
		if len(value.Items) != 2 || value.Items[0].Health == nil {
			t.Fatal("path configuration references lost their owned current hop")
		}
		health := value.Items[0].Health
		if health.ConfigCoverage != "operator_bound_archives" || len(health.ConfigChanges) != 501 {
			t.Fatal("complete original config history was capped or joined by display name", health.ConfigCoverage, len(health.ConfigChanges))
		}
		for i, ref := range health.ConfigChanges {
			want := originals[tenant][i]
			if ref.ID != want.ID || ref.ContentHash != want.ContentHash || ref.Version != i+1 || ref.Binding.ContextID != f.contextID || ref.Binding.DeviceEntityID != f.routerID || ref.Binding.Kind != "operator_bound_archive" || !ref.Binding.SourceAssignedAt.Equal(want.Binding.SourceAssignedAt) {
				t.Fatal("configuration reference changed its original identity/source stream", i)
			}
			if i > 0 && (ref.ChangeStatus != "original_predecessor_verified" || ref.PreviousID != originals[tenant][i-1].ID || ref.PreviousHash != originals[tenant][i-1].ContentHash) {
				t.Fatal("config change lacks its exact original predecessor", i)
			}
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "description revision") || strings.Contains(string(raw), "LEGACY_MUST_NOT_ATTACH") {
			t.Fatal("path configuration references included stored content or an unbound archive")
		}
	}
	for _, tenant := range f.tenants {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/tests/"+proof.tests[tenant]+"/path/entities?"+proof.windows[tenant].Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatal("served path archive refused", response.StatusCode, err, string(raw))
		}
		var value pathHealthResult
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		check(tenant, value)
		params := proof.windows[tenant]
		yes, from, to, gap, maximum := true, params.Get("health_from"), params.Get("health_to"), params.Get("health_poll_gap"), params.Get("health_max_bps")
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		typed, err := client.GetPathEntities(t.Context(), sdk.GetPathEntitiesRequest{Id: proof.tests[tenant], IncludeHealth: &yes, HealthFrom: &from, HealthTo: &to, HealthPollGap: &gap, HealthMaxBps: &maximum})
		if err != nil {
			t.Fatal(err)
		}
		raw, err = json.Marshal(typed)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		check(tenant, value)
		ca := filepath.Join(t.TempDir(), "archive-ca.pem")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"--json", "entities", "path-resolve", proof.tests[tenant]}
		for key, values := range params {
			args = append(args, "--query", key+"="+values[0])
		}
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		var stdout, stderr bytes.Buffer
		if code := cli.RunWithStdin(args, getenv, nil, &stdout, &stderr); code != 0 {
			t.Fatal("path config CLI failed", code, stderr.String())
		}
		if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		check(tenant, value)
	}
	seedInterfaceRoleMCPConsent(f)
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for _, tenant := range f.tenants {
			args := map[string]any{"test_id": proof.tests[tenant]}
			for key, values := range proof.windows[tenant] {
				if key != "include_health" {
					args[key] = values[0]
				}
			}
			var value pathHealthResult
			call(tenant, "path_interface_health", args, &value, true)
			check(tenant, value)
			args["question"] = "Explain original interface observations and operator archive changes without assuming causation."
			var answer ai.Answer
			call(tenant, "path_interface_health_explain", args, &answer, true)
			if len(answer.Evidence) != 1 || !answer.RootCauseGrounded || len(answer.RootCauseCitations) == 0 || answer.RootCauseCitations[0].EvidenceID != answer.Evidence[0].ID {
				t.Fatal("configuration RCA omitted exact citations")
			}
			raw, err := json.Marshal(answer.Evidence[0].Fields["path_health"])
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			check(tenant, value)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	model.after = func() {
		model.after = nil
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM device_configs WHERE tenant_id=$1 AND id=$2`, a, originals[a][500].ID)
			return err
		})
	}
	call := interfaceRoleNativeTLSCaller(t, f, "2026-07-28")
	args := func(tenant string) map[string]any {
		value := map[string]any{"test_id": proof.tests[tenant], "question": "Explain original interface and operator archive observations."}
		for key, values := range proof.windows[tenant] {
			if key != "include_health" {
				value[key] = values[0]
			}
		}
		return value
	}
	call(a, "path_interface_health_explain", args(a), nil, false)
	var sibling ai.Answer
	call(b, "path_interface_health_explain", args(b), &sibling, true)
	raw, err := json.Marshal(sibling.Evidence[0].Fields["path_health"])
	if err != nil {
		t.Fatal(err)
	}
	var value pathHealthResult
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	check(b, value)
	t.Log("real-integration: complete501 original archive references per tenant through verified TLS API/SDK/CLI and both native HTTP revisions with cited RCA and late erasure/sibling control; configs/path/SNMP/history modeled operator inputs, physical collection/lab remains owed")
}
