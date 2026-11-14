// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func opticalFleetSamples(tenant string, lane int) []tsdb.Series {
	var samples []tsdb.Series
	for component := range 512 {
		for _, channel := range []string{"", "0", "1"} {
			for _, metric := range []string{"input_power_dbm", "output_power_dbm", "laser_bias_milliamperes", "supply_voltage_volts", "temperature_celsius"} {
				if channel != "" && (metric == "supply_voltage_volts" || metric == "temperature_celsius") {
					continue
				}
				name := "probectl_device_optical_" + metric
				if metric == "temperature_celsius" {
					name = "probectl_device_sensor_temperature_celsius"
				}
				samples = append(samples, tsdb.Series{Metric: name, Labels: map[string]string{
					"tenant_id": tenant, "agent_id": "same-agent", "device": "192.0.2.50", "source": "gnmi", "component": fmt.Sprintf("optic-%04d", component), "physical_channel": channel,
				}, Value: -3.25 - float64(lane*1000) - map[string]float64{"": 0, "0": 1, "1": 2}[channel], TimeMillis: time.Now().UnixMilli()})
			}
		}
	}
	return samples
}

func TestDeviceOpticalMetricsKeepCompleteAdmittedFleetAndTenantScope(t *testing.T) {
	writer := tsdb.NewMemory()
	owner := tenancy.DefaultTenantID.String()
	var samples []tsdb.Series
	for lane, tenant := range []string{owner, otherTenant} {
		samples = append(samples, opticalFleetSamples(tenant, lane)...)
	}
	if err := writer.Write(t.Context(), samples); err != nil {
		t.Fatal(err)
	}
	resources := flowstore.NewMemory()
	budget := flowstore.DefaultExplorerBudget()
	budget.MemoryBytes = 1 << 20
	if err := flowstore.AttachExplorerBudget(resources, budget); err != nil {
		t.Fatal(err)
	}
	server := testServer(fakePinger{}).WithTSDB(writer).WithFlowStore(resources).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	const path = "/v1/device/metrics?limit=50000"
	refused := do(server, http.MethodGet, path)
	if refused.Code != http.StatusRequestEntityTooLarge || strings.Contains(refused.Body.String(), "optic-0000") || strings.Contains(refused.Body.String(), `"items"`) {
		t.Fatal("underfunded complete optical fleet returned a successful prefix", refused.Code)
	}
	budget.MemoryBytes = 256 << 20
	if err := flowstore.AttachExplorerBudget(resources, budget); err != nil {
		t.Fatal(err)
	}
	response := do(server, http.MethodGet, path)
	var result struct {
		Items []deviceMetricSummary `json:"items"`
		Limit int                   `json:"effective_limit"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.Items) != 5632 || result.Limit != 50000 {
		t.Fatal("complete512-component optical fleet was clamped to an old number", response.Code, len(result.Items), result.Limit)
	}
	seen := map[string]bool{}
	for _, item := range result.Items {
		if item.Component == "" || item.IfIndex != "" || item.IfName != "" || seen[item.ID] {
			t.Fatal("component/channel identity collapsed or invented a canonical port", item)
		}
		seen[item.ID] = true
		want := map[string]float64{"": -3.25, "0": -4.25, "1": -5.25}[item.PhysicalChannel]
		if item.Value != want {
			t.Fatal("paired tenant optical values crossed the storage selector", item.Component, item.PhysicalChannel, item.Value)
		}
	}
	if strings.Contains(response.Body.String(), otherTenant) {
		t.Fatal("paired tenant metadata escaped the scoped metric selector")
	}
}
