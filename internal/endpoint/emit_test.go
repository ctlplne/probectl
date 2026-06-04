package endpoint

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// captureBus records every Publish for assertions.
type captureBus struct {
	msgs []capMsg
}

type capMsg struct {
	topic string
	key   []byte
	value []byte
}

func (c *captureBus) Publish(_ context.Context, topic string, key, value []byte) error {
	c.msgs = append(c.msgs, capMsg{topic, key, value})
	return nil
}
func (c *captureBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (c *captureBus) Close() error                                                 { return nil }

// TestBusEmitterPublishesTenantTaggedResults checks the DEM sample lands on
// probectl.endpoint.results as canonical resultv1.Result messages, tenant-keyed,
// with the attribution result carrying the cause.
func TestBusEmitterPublishesTenantTaggedResults(t *testing.T) {
	cb := &captureBus{}
	em := NewBusEmitter(cb, "tenant-A", "laptop-7")

	s := Sample{
		TenantID: "tenant-A", AgentID: "laptop-7", Timestamp: time.Unix(1700000000, 0),
		WiFi:     WiFi{Present: true, Associated: true, RSSIDBm: -84, Have: WiFiHave{RSSI: true}},
		Gateway:  Gateway{IP: "192.168.1.1", Reachable: true, RTTMs: 30},
		LastMile: LastMile{Target: "1.1.1.1", ISPRTTMs: 40, Hops: []LastMileHop{{Index: 1, IP: "192.168.1.1", Private: true, RTTMs: 30}}},
		Sessions: []Session{{Target: "https://app", Success: true, TotalMs: 2200}},
	}
	s.Attribution = Attribute(s, DefaultThresholds())

	if err := em.Emit(context.Background(), s); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(cb.msgs) == 0 {
		t.Fatal("no messages published")
	}

	var sawAttribution bool
	for _, m := range cb.msgs {
		if m.topic != bus.EndpointResultsTopic {
			t.Errorf("topic = %q, want %q", m.topic, bus.EndpointResultsTopic)
		}
		if string(m.key) != "tenant-A" {
			t.Errorf("key (tenant tag) = %q, want tenant-A", m.key)
		}
		var r resultv1.Result
		if err := proto.Unmarshal(m.value, &r); err != nil {
			t.Fatalf("payload not a resultv1.Result: %v", err)
		}
		if r.TenantId != "tenant-A" || r.AgentId != "laptop-7" {
			t.Errorf("identity not stamped: %+v", &r)
		}
		if r.CanaryType == TypeAttribution {
			sawAttribution = true
			if r.Attributes["endpoint.cause"] != string(CauseWiFi) {
				t.Errorf("attribution cause = %q, want wifi", r.Attributes["endpoint.cause"])
			}
		}
	}
	if !sawAttribution {
		t.Errorf("expected an attribution result among %d messages", len(cb.msgs))
	}
}
