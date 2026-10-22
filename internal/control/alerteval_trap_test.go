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

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/device"
)

type fakeTrapMatches struct {
	rows   map[string][]device.TrapMatch
	tenant string
	query  device.TrapMatchQuery
}

func (f *fakeTrapMatches) LatestTrapMatches(_ context.Context, tenant string, q device.TrapMatchQuery) ([]device.TrapMatch, error) {
	f.tenant, f.query = tenant, q
	return f.rows[tenant], nil
}

func TestTrapSourceMapsNewestMatchesToSamples(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	linkDown, linkUp := ".1.3.6.1.6.3.1.1.5.3", ".1.3.6.1.6.3.1.1.5.4"
	reader := &fakeTrapMatches{rows: map[string][]device.TrapMatch{
		"tenant-a": {
			{DeviceAddress: "10.0.0.1", TrapOID: linkDown, ReceivedAt: now.Add(-time.Minute)},      // held
			{DeviceAddress: "10.0.0.2", TrapOID: linkUp, ReceivedAt: now.Add(-time.Minute)},        // cleared
			{DeviceAddress: "10.0.0.3", TrapOID: linkDown, ReceivedAt: now.Add(-16 * time.Minute)}, // expired
		},
		"tenant-b": {{DeviceAddress: "10.0.0.1", TrapOID: linkDown, ReceivedAt: now}},
	}}
	rule := alert.Rule{Name: "uplink", Type: alert.Trap, Trap: &alert.TrapMatch{
		TrapOID: linkDown, ClearTrapOID: linkUp, VarBindOID: ".1.3.6.1.2.1.2.2.1.1.2", VarBindValue: "2", HoldSeconds: 900,
	}}
	samples, err := trapSource{traps: reader, tenant: "tenant-a"}.ActiveTraps(context.Background(), rule, now)
	if err != nil {
		t.Fatal(err)
	}
	if reader.tenant != "tenant-a" || reader.query.TrapOID != linkDown || reader.query.ClearTrapOID != linkUp ||
		reader.query.VarBindValue != "2" || !reader.query.Since.Equal(now.Add(-(15*time.Minute + trapResolveLookback))) {
		t.Fatalf("query = %s %+v", reader.tenant, reader.query)
	}
	want := map[string]float64{"10.0.0.1": 1, "10.0.0.2": 0, "10.0.0.3": 0}
	reasons := map[string]string{"10.0.0.1": "linkDown trap from 10.0.0.1", "10.0.0.2": "clear trap linkUp", "10.0.0.3": "hold ran out"}
	if len(samples) != 3 {
		t.Fatalf("samples = %+v", samples)
	}
	for _, s := range samples {
		d := s.Labels["device"]
		if s.Value != want[d] || !strings.Contains(s.Reason, reasons[d]) || s.Labels["trap_oid"] != linkDown || s.Labels["trap_name"] != "linkDown" {
			t.Errorf("sample for %s = %+v", d, s)
		}
		for k := range s.Labels {
			if k == "tenant_id" || strings.Contains(s.Labels[k], "2026") {
				t.Errorf("sample labels carry %s=%s; a series key must not hold a tenant or a time", k, s.Labels[k])
			}
		}
	}
}
