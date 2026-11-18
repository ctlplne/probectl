// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSeasonalTestSourcePinsCurrentOwnedRevision(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	memory := tsdb.NewMemory()
	f.server.WithTSDB(memory).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	now := time.Now().UTC().Truncate(time.Millisecond)
	const metric = "probectl_probe_rtt_avg_ms"
	var testIDs, paths [2]string
	var rules [2]alert.Rule
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAlertRead, permAlertWrite, "test.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			st, err := (store.Tests{}).Create(ctx, sc, store.TestInput{Name: "Owned test", Type: "icmp", Target: "192.0.2.5", IntervalSeconds: 60, TimeoutSeconds: 5, Enabled: true})
			if err != nil {
				return err
			}
			testIDs[lane] = st.ID
			_, err = sc.Q.Exec(ctx, `UPDATE tests SET created_at=$3,updated_at=$3 WHERE tenant_id=$1 AND id=$2`, tenant, st.ID, now.AddDate(0, 0, -25))
			return err
		})
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/alerts", map[string]any{
			"name": "Current test history", "metric": metric, "type": "baseline", "window": 20, "sensitivity": 3,
		}, http.StatusCreated)
		if err := json.Unmarshal(raw, &rules[lane]); err != nil {
			t.Fatal(err)
		}
		paths[lane] = "/v1/alerts/rules/" + rules[lane].ID + "/seasonal-source"
	}
	for lane, tenant := range f.tenants {
		input := alert.SeasonalBaselineInput{Timezone: "UTC", MinimumChange: 5, TestID: testIDs[1-lane]}
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, paths[lane], input, http.StatusNotFound)
		input.TestID = testIDs[lane]
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, paths[lane], input, http.StatusOK)
		model, err := input.Model()
		if err != nil {
			t.Fatal(err)
		}
		var offered []tsdb.Series
		labels := map[string]string{tsdb.TenantLabel: tenant, "test_id": testIDs[lane]}
		for i, window := range model.ComparableWindows(now) {
			level := 50.0
			if i < 3 {
				level = 900 // prior test revision is outside the current history
			}
			offered = append(offered, tsdb.Series{Metric: metric, Labels: labels, TimeMillis: window.Start.UnixMilli(), Value: level})
		}
		offered = append(offered, tsdb.Series{Metric: metric, Labels: labels, TimeMillis: now.UnixMilli(), Value: 80})
		if err := memory.Write(t.Context(), offered); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			stored, err := (store.AlertRules{}).Get(ctx, sc, rules[lane].ID)
			if err == nil {
				rules[lane] = *stored
			}
			return err
		})
	}
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		read, err := f.server.readSeasonalMetricRule(ctx, rules[lane], now)
		if err != nil || len(read.Samples) != 1 || read.Samples[0].Labels["test_id"] != testIDs[lane] ||
			read.Samples[0].Seasonal.State != anomaly.SeasonalUp || read.Samples[0].Seasonal.Evidence.Median != 50 ||
			read.Samples[0].Seasonal.TrainingWindow.Samples != 3 {
			t.Fatalf("selected current test did not use only its exact revision: %+v (%v)", read, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE tests SET updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, testIDs[lane])
			return err
		})
		if read, err := f.server.readSeasonalMetricRule(ctx, rules[lane], now); !errors.Is(err, store.ErrAlertSeasonalChanged) || len(read.Samples) != 0 {
			t.Fatal("superseded test revision remained eligible for scoring", err)
		}
	}
}
