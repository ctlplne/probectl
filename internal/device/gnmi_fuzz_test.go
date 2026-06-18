// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"math"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	gnmipb "github.com/imfeelingtheagi/probectl/internal/gen/gnmi"
)

func FuzzGNMINormalize(f *testing.F) {
	for _, n := range []*gnmipb.Notification{
		gnmiFuzzNotification("eth0", "in-octets", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 42}}),
		gnmiFuzzNotification("xe-0/0/0", "oper-status", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "UP"}}),
		gnmiFuzzNotification("bad", "in-octets", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: math.Inf(1)}}),
	} {
		b, err := proto.Marshal(n)
		if err != nil {
			f.Fatalf("marshal seed: %v", err)
		}
		f.Add(b)
	}

	c := &gnmiCollector{
		dev:    Target{Address: "192.0.2.99"},
		tenant: "tenant-fuzz",
		agent:  "agent-fuzz",
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var n gnmipb.Notification
		if err := proto.Unmarshal(data, &n); err != nil {
			return
		}
		ms := c.normalize(&n)
		if len(ms) > len(n.GetUpdate()) {
			t.Fatalf("normalize emitted %d metrics from %d updates", len(ms), len(n.GetUpdate()))
		}
		for _, m := range ms {
			if m.TenantID != "tenant-fuzz" || m.AgentID != "agent-fuzz" || m.Source != SourceGNMI {
				t.Fatalf("metric escaped collector identity: %+v", m)
			}
			if math.IsNaN(m.Value) || math.IsInf(m.Value, 0) {
				t.Fatalf("metric carried non-finite value: %+v", m)
			}
			if m.At.IsZero() {
				t.Fatalf("metric timestamp is zero: %+v", m)
			}
		}
	})
}

func gnmiFuzzNotification(ifName, leaf string, val *gnmipb.TypedValue) *gnmipb.Notification {
	return &gnmipb.Notification{
		Timestamp: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC).UnixNano(),
		Prefix:    &gnmipb.Path{Target: "fuzz-device"},
		Update: []*gnmipb.Update{
			{
				Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
					{Name: "interfaces"},
					{Name: "interface", Key: map[string]string{"name": ifName}},
					{Name: "state"},
					{Name: "counters"},
					{Name: leaf},
				}},
				Val: val,
			},
		},
	}
}
