// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/otel"
)

func TestSLOConsumerHTTPHostnameSelector(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		attrs        map[string]string
	}{
		{name: "current agent URL", target: "https://web.acme.example:8443/checkout", attrs: map[string]string{otel.AttrServerAddress: "web.acme.example"}},
		{name: "URL without host attribute", target: "https://web.acme.example:8443/checkout"},
		{name: "legacy host", target: "web.acme.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := sloTestEngine(t)
			at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
			eng.WithClock(func() time.Time { return at })
			sc := NewSLOConsumer(nil, eng, nil, intelTestLog())
			sc.clock = func() time.Time { return at }
			push := func(payloadTenant, keyTenant string, success bool) {
				raw, err := proto.Marshal(&resultv1.Result{TenantId: payloadTenant, CanaryType: "http", ServerAddress: tc.target, Attributes: tc.attrs, Success: success, StartTimeUnixNano: at.UnixNano()})
				if err != nil {
					t.Fatal(err)
				}
				if err := sc.handleLane(context.Background(), bus.Message{Key: bus.TenantKey(keyTenant, "agent"), Value: raw}, ""); err != nil {
					t.Fatal(err)
				}
			}
			push("red", "red", false)
			push("blue", "blue", true)
			push("blue", "red", false) // forged tenant is refused before matching
			for _, want := range []struct {
				tenant     string
				attainment float64
			}{{"red", 0}, {"blue", 1}} {
				got := eng.Statuses(want.tenant)
				if len(got) != 1 || got[0].TotalEvents != 1 || got[0].Attainment != want.attainment {
					t.Fatalf("%s status=%+v", want.tenant, got)
				}
			}
		})
	}
}
