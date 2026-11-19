// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestGoldenFieldReplaysKeepEveryOriginalDimensionInTwoTenantReaders(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	rows := seasonalFlowFixtureStore(t, f, true)
	queries := flow.NewPostgresQueryViewStore(f.pool, 0, audit.TenantRecord)
	f.server.WithFlowStore(rows).WithFlowQueryViews(queries).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	windows, err := anomaly.FlowFieldCompletedWindows(time.Now(), anomaly.FlowFieldCompleteWeek, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		grantSeasonalFlowFixture(f, tenant)
	}
	for i, item := range goldenFlowFieldCases() {
		t.Run(item.name, func(t *testing.T) {
			exporter := fmt.Sprintf("203.0.113.%d", 21+i)
			measure, calculation, _ := strings.Cut(item.measure, ":")
			var selected [2]flow.SavedQueryView
			for lane, tenant := range f.tenants {
				ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
				definition := fieldComparisonViewDefinition("Controlled " + item.name)
				definition.Plan.GroupBy = []string{item.field}
				definition.Plan.Metrics = []flow.QueryMetric{{Measure: measure, Calculation: calculation, Role: "primary"}}
				definition.Plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{
					{Field: "exporter", Op: flow.QueryEqual, Values: []string{exporter}},
				}}
				view, err := queries.SaveQueryView(ctx, tenant, f.users[tenant], flow.SaveQueryView{Definition: definition})
				if err != nil {
					t.Fatal(err)
				}
				selected[lane] = view
				seedGoldenFieldReplays(t, rows, tenant, exporter, item, windows, lane == 0)
			}
			input := flow.FieldComparisonInput{Version: selected[0].Version, Mode: item.mode, Cadence: "complete_week", Measure: item.measure, TopKeys: item.top}
			switch item.mode {
			case "rank":
				input.MinimumChange = "100"
			case "share":
				input.ShareBasisPoints = 1000
			case "fanout":
				input.MinimumChange = "4"
			}
			var owned, stable flow.FieldComparison
			for lane, target := range []*flow.FieldComparison{&owned, &stable} {
				tenant, view := f.tenants[lane], selected[lane]
				endpoint := "/v1/explorer/flow-views/" + view.ID + "/field-comparison"
				raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, endpoint, input, http.StatusOK)
				if err := json.Unmarshal(raw, target); err != nil {
					t.Fatal(err)
				}
				callSeasonalAPI(t, socket, f.tokens[f.tenants[1-lane]], http.MethodPost, endpoint, input, http.StatusNotFound)
			}
			if owned.ViewID != selected[0].ID || stable.ViewID != selected[1].ID || len(stable.Changes) != 0 || len(owned.Changes) != 1 ||
				owned.Changes[0].Kind != item.kind || owned.Changes[0].After == nil || owned.Changes[0].After.Citation == "" ||
				!owned.Before.From.Equal(windows.Before.Start) || !owned.After.To.Equal(windows.After.End) {
				t.Fatal("real source replay omitted or duplicated the planted comparison or crossed tenants", owned.Changes, stable.Changes)
			}
		})
	}
}

func seedGoldenFieldReplays(t *testing.T, store flowstore.Store, tenant, exporter string, item goldenFieldCase, windows anomaly.FlowFieldComparisonClocks, changed bool) {
	t.Helper()
	var batch []flowstore.Row
	for period, window := range []anomaly.TrainingWindow{windows.Before, windows.After} {
		at := window.Start.Add(time.Hour)
		records := item.before
		if period == 1 && changed {
			records = item.after
		}
		for i, sample := range records {
			count, err := strconv.ParseUint(sample.value, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			row := flowstore.Row{TenantID: tenant, AgentID: "field-dimension-golden", Exporter: exporter, Protocol: "ipfix",
				TS: at, StartTS: at.Add(-time.Second), SrcAddr: "192.0.2.135", DstAddr: "198.51.100.136", SrcPort: uint16(42000 + i), DstPort: 443,
				Transport: "tcp", Sampling: 1, Bytes: count, BytesScaled: count, Packets: 1, PacketsScaled: 1}
			switch item.field {
			case "src_addr":
				row.SrcAddr = sample.group
			case "dst_addr":
				row.DstAddr = sample.group
			case "src_country":
				row.SrcCountry = sample.group
			case "dst_asn":
				asn, err := strconv.ParseUint(sample.group, 10, 32)
				if err != nil {
					t.Fatal(err)
				}
				row.DstASN = uint32(asn)
			case "dst_port":
				port, err := strconv.ParseUint(sample.group, 10, 16)
				if err != nil {
					t.Fatal(err)
				}
				row.DstPort = uint16(port)
			case "transport":
				row.Transport = sample.group
			}
			if item.mode != "fanout" {
				batch = append(batch, row)
				continue
			}
			for destination := range count {
				row.DstAddr = fmt.Sprintf("198.51.100.%d", 150+destination)
				batch = append(batch, row)
			}
			row.SrcPort++
			batch = append(batch, row) // another packet to the last destination
		}
	}
	if err := store.Insert(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
}
