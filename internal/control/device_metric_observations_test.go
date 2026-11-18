// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/tsdb"
)

type deviceSampleQueryFunc func(string, time.Time) ([]tsdb.LabeledSample, error)

func (f deviceSampleQueryFunc) InstantVectorAt(_ context.Context, query string, at time.Time, _ int64) ([]tsdb.LabeledSample, error) {
	return f(query, at)
}

func TestDeviceMetricQueryBindsOriginalSampleTimesToExactTenantSeries(t *testing.T) {
	const energy = "probectl_device_optical_input_power_dbm"
	const voltage = "probectl_device_optical_supply_voltage_volts"
	const device = "192.0.2.50"
	observed := time.Now().UTC().Truncate(time.Millisecond).Add(-45 * time.Second)
	for _, failure := range []string{"", "missing", "duplicate", "foreign"} {
		t.Run("series/"+failure, func(t *testing.T) {
			for _, tenant := range []string{"tenant-a", "tenant-b"} {
				var evaluation time.Time
				labels := func(metric, owner string) map[string]string {
					return map[string]string{"__name__": metric, "tenant_id": owner, "device": device, "component": "optic-0001"}
				}
				q := deviceSampleQueryFunc(func(query string, at time.Time) ([]tsdb.LabeledSample, error) {
					scope := `device="192.0.2.50",tenant_id="` + tenant + `"`
					if evaluation.IsZero() {
						evaluation = at
						if at.IsZero() || !strings.HasPrefix(query, "group by (__name__, tenant_id)") || !strings.Contains(query, scope) {
							t.Fatal("metric name lookup was not scoped to the selected tenant and device")
						}
						return []tsdb.LabeledSample{
							{Labels: map[string]string{"__name__": energy, "tenant_id": tenant}},
							{Labels: map[string]string{"__name__": voltage, "tenant_id": tenant}},
						}, nil
					}
					if !evaluation.Equal(at) || strings.Count(query, scope) != 3 || strings.Count(query, "or on (__name__)") != 2 {
						t.Fatal("values and stored times were not read together under the same tenant/device selectors and evaluation time")
					}
					result := []tsdb.LabeledSample{
						{Labels: labels(energy, tenant), Value: -3.25},
						{Labels: labels(voltage, tenant), Value: 4.8},
						{Labels: labels(deviceSampleTimePrefix+voltage, tenant), Value: float64(observed.UnixMilli()-1234) / 1000},
						{Labels: labels(deviceSampleTimePrefix+energy, tenant), Value: float64(observed.UnixMilli()) / 1000},
					}
					switch failure {
					case "missing":
						result = result[:3]
					case "duplicate":
						result[3] = result[2]
					case "foreign":
						result[3].Labels["tenant_id"] = tenant + "-foreign"
					}
					return result, nil
				})
				rows, err := deviceMetricSeriesFromTSDB(t.Context(), q, tenant, device, "", 1<<20)
				if failure != "" {
					if err == nil || rows != nil {
						t.Fatal("incomplete or mismatched observation returned rows")
					}
					continue
				}
				if err != nil || len(rows) != 2 || rows[0].TimeMillis != observed.UnixMilli() || rows[1].TimeMillis != observed.UnixMilli()-1234 ||
					rows[0].Metric != energy || rows[0].Value != -3.25 || rows[1].Metric != voltage || rows[1].Value != 4.8 {
					t.Fatalf("stored timestamps were not joined to their exact optical samples: %v (%v)", rows, err)
				}
			}
		})
	}
}
