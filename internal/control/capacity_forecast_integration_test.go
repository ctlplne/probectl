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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Actual TLS PG/app-role RLS, verified HTTPS, generated SDK/CLI and native HTTPS.
// Counter words and original receipt rows are modeled, not a physical SNMP or
// new issued-transport sender proof.
func TestCapacityForecastServesKnownGrowthWithoutFinancialAccessAndKeepsCurrentTenants(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	var diagnostics bytes.Buffer
	f.server.log = slog.New(slog.NewTextHandler(&diagnostics, nil))
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(diagnostics.String())
		}
	})
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	probe := &capacityCounterHistoryProbe{Memory: flowstore.NewMemory()}
	f.server.flowStore = probe
	from := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	to, until := from.Add(14*24*time.Hour), from.Add(20*24*time.Hour)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permFlowRead)
		})
		seedCapacityCounterPeriod(f, probe.Memory, tenant, from, to, true)
	}
	seedInterfaceRoleMCPConsent(f)
	input := flow.CapacityForecastRequest{Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, From: from.Format(time.RFC3339Nano), To: to.Format(time.RFC3339Nano), Until: until.Format(time.RFC3339Nano), Direction: "max_directional_percentiles", CapacityBPS: "12000000", MaximumPollGap: "5m", PhysicalBounds: []flow.CapacityPhysicalBound{{ContextID: f.contextID, InterfaceID: f.interfaceID, MaxBPS: "50000000"}}}
	raw, _ := json.Marshal(input)
	var sdkInput sdk.CapacityForecastInput
	if err := json.Unmarshal(raw, &sdkInput); err != nil {
		t.Fatal(err)
	}
	var hand time.Time
	for i := int64(4032); i < 20*24*12; i++ {
		if 8_000_000+800*i+400+80*(i%288) >= 12_000_000 {
			hand = from.Add(time.Duration(i) * 5 * time.Minute)
			break
		}
	}
	if hand.IsZero() {
		t.Fatal("independent generating curve did not cross selected threshold")
	}
	assertForecast := func(got flow.CapacityForecastMeasurement) {
		t.Helper()
		if len(got.Forecasts) != 2 || len(got.Members) != 1 || got.Target != input.Target || got.MembershipBasis != "current_member_set_applied_to_complete_period" {
			t.Fatal("complete current forecast target/member model was lost", got)
		}
		for _, forecast := range got.Forecasts {
			if !forecast.Trained || !forecast.CoverageComplete || forecast.ExpectedSamples != 4032 || forecast.ObservedSamples != 4032 || forecast.IntervalMethod != "in_sample_residual_envelope" || !forecast.From.Equal(from) || !forecast.To.Equal(to) {
				t.Fatal("complete training period or weekly model was lost", forecast)
			}
			if forecast.Direction == "out" {
				if forecast.TrendNumerator != "0" || forecast.Central.Reached || forecast.Reason != "threshold_not_reached_in_horizon" {
					t.Fatal("flat outbound series inherited inbound growth", forecast)
				}
				continue
			}
			if forecast.TrendNumerator != "230400" || forecast.TrendDenominator != "1" {
				t.Fatal("exact original-counter trend differs from generating slope", forecast)
			}
			for _, interval := range []flow.CapacityRunoutInterval{forecast.Central, forecast.Earliest, forecast.Latest} {
				if !interval.Reached || interval.From == nil || interval.To == nil || !interval.From.Equal(hand) || !interval.To.Equal(hand.Add(5*time.Minute)) {
					t.Fatal("runout missed independent generating-curve oracle by more than its five-minute interval", interval, hand)
				}
			}
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		result, err := client.ForecastCapacity(t.Context(), sdk.ForecastCapacityRequest{Body: &sdkInput})
		if err != nil || result == nil {
			t.Fatal("nonfinancial generated forecast client failed", err)
		}
		encoded, _ := json.Marshal(result)
		var got flow.CapacityForecastMeasurement
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatal(err)
		}
		assertForecast(got)
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if code := cli.RunWithStdin([]string{"--json", "capacity", "forecast", "--body-file", "-"}, getenv, bytes.NewReader(raw), &stdout, &stderr); code != 0 {
			t.Fatal("verified TLS forecast CLI failed", code, stderr.String())
		}
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		assertForecast(got)
	}
	// The same complete original history is also reachable through current
	// effective circuit membership, without requiring a flow exporter.
	tagID := gouuid.NewString()
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permTagsRead); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES($1,$2,'forecast_circuit')`, tenant, tagID); err != nil {
				return err
			}
			_, err := (store.TagAssignments{}).CreateManual(ctx, sc, store.ManualTagAssignmentInput{Scope: tags.Scope{TenantID: tenant, ContextID: f.contextID}, TagID: tagID, TargetKind: "interface", TargetID: f.interfaceID, Value: "transit"})
			return err
		})
	}
	interfaceTarget := input.Target
	input.Target = flow.CapacityTarget{Kind: "circuit", TagID: tagID, TagValue: "transit"}
	circuitRaw, _ := json.Marshal(input)
	var circuitInput sdk.CapacityForecastInput
	if err := json.Unmarshal(circuitRaw, &circuitInput); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		result, err := client.ForecastCapacity(t.Context(), sdk.ForecastCapacityRequest{Body: &circuitInput})
		if err != nil || result == nil {
			t.Fatal("complete current circuit forecast failed", err)
		}
		encoded, _ := json.Marshal(result)
		var got flow.CapacityForecastMeasurement
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatal(err)
		}
		assertForecast(got)
	}
	input.Target = interfaceTarget
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for _, tenant := range f.tenants {
			var got flow.CapacityForecastMeasurement
			call(tenant, "capacity_forecast", map[string]any{"forecast": input}, &got, true)
			assertForecast(got)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	request := func(tenant string) (int, flow.CapacityForecastMeasurement) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/flows/capacity/forecast", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		r.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var got flow.CapacityForecastMeasurement
		_ = json.NewDecoder(response.Body).Decode(&got)
		return response.StatusCode, got
	}
	probe.transform = func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
		for i := range rows {
			rows[i].TenantID = b
		}
		return rows, nil
	}
	if status, got := request(a); status != http.StatusServiceUnavailable || len(got.Forecasts) != 0 {
		t.Fatal("foreign backend rows published a forecast", status, got)
	}
	probe.transform = nil
	probe.after = func() {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='metrics.read'`, a, f.roles[a])
			return err
		})
	}
	if status, got := request(a); status != http.StatusForbidden || len(got.Forecasts) != 0 {
		t.Fatal("current metric withdrawal published trained runout", status, got)
	}
	probe.after = nil
	if status, got := request(b); status != http.StatusOK {
		t.Fatal("source denial damaged sibling forecast", status)
	} else {
		assertForecast(got)
	}
}
