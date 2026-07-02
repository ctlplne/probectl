// SPDX-License-Identifier: LicenseRef-probectl-TBD

package bgp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// An origin-change event as the Python analyzer emits it (JSON Lines).
const originChange = `{"tenant_id":"t1","event_type":"origin_change","severity":"warning",` +
	`"confidence":0.7,"prefix":"192.0.2.0/24","new_origin_asn":64500,"old_origin_asn":64496,` +
	`"new_as_path":[64511,64500],"old_as_path":[64511,64496],"expected_origins":[64496],` +
	`"rpki_status":"invalid","collector":"rrc00","peer_asn":64511,"peer_address":"192.0.2.1",` +
	`"message":"origin changed","detected_at_unix_nano":1700000000000000000}`

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type capturedMsg struct {
	topic string
	key   []byte
	value []byte
}

type capturePublisher struct {
	mu   sync.Mutex
	msgs []capturedMsg
	err  error
}

func (c *capturePublisher) Publish(_ context.Context, topic string, key, value []byte) error {
	if c.err != nil {
		return c.err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, capturedMsg{topic, append([]byte(nil), key...), append([]byte(nil), value...)})
	return nil
}

type testIsolationRouter struct {
	targets map[string]tenancy.Targets
	err     error
}

func (r testIsolationRouter) TargetsFor(_ context.Context, tenantID string) (tenancy.Targets, error) {
	if r.err != nil {
		return tenancy.Targets{}, r.err
	}
	return r.targets[tenantID], nil
}

func (r testIsolationRouter) BusNamespaces(context.Context) ([]string, error) { return nil, nil }

func (r testIsolationRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

func withTestRouter(t *testing.T, r tenancy.Router) {
	t.Helper()
	prev := tenancy.CurrentRouter()
	tenancy.SetRouter(r)
	t.Cleanup(func() { tenancy.SetRouter(prev) })
}

func TestBridgePublishesTenantKeyedEvent(t *testing.T) {
	pub := &capturePublisher{}
	br := NewBridge(pub, discardLogger())

	stats, err := br.Ingest(context.Background(), strings.NewReader(originChange+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Published != 1 || stats.Skipped != 0 {
		t.Fatalf("stats = %+v, want 1 published / 0 skipped", stats)
	}
	if len(pub.msgs) != 1 {
		t.Fatalf("published %d messages, want 1", len(pub.msgs))
	}
	msg := pub.msgs[0]
	if msg.topic != bus.BGPEventsTopic {
		t.Errorf("topic = %q, want %q", msg.topic, bus.BGPEventsTopic)
	}
	if string(msg.key) != "t1" {
		t.Errorf("key = %q, want tenant t1", msg.key)
	}

	var ev bgpv1.BGPEvent
	if err := proto.Unmarshal(msg.value, &ev); err != nil {
		t.Fatalf("unmarshal published proto: %v", err)
	}
	if ev.GetEventType() != bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE {
		t.Errorf("event_type = %v", ev.GetEventType())
	}
	if ev.GetPrefix() != "192.0.2.0/24" {
		t.Errorf("prefix = %q", ev.GetPrefix())
	}
	if ev.GetOldOriginAsn() != 64496 || ev.GetNewOriginAsn() != 64500 {
		t.Errorf("origins = %d -> %d, want 64496 -> 64500", ev.GetOldOriginAsn(), ev.GetNewOriginAsn())
	}
	if got := ev.GetNewAsPath(); len(got) != 2 || got[0] != 64511 || got[1] != 64500 {
		t.Errorf("new_as_path = %v", got)
	}
	if ev.GetRpkiStatus() != bgpv1.RpkiStatus_RPKI_STATUS_INVALID {
		t.Errorf("rpki_status = %v, want INVALID", ev.GetRpkiStatus())
	}
	if ev.GetSeverity() != bgpv1.Severity_SEVERITY_WARNING {
		t.Errorf("severity = %v", ev.GetSeverity())
	}
}

func TestBridgePublishesThroughTenantBusNamespace(t *testing.T) {
	withTestRouter(t, testIsolationRouter{targets: map[string]tenancy.Targets{
		"t1": {Model: tenancy.IsolationHybrid, BusNamespace: "tenant-one"},
	}})
	pub := &capturePublisher{}

	if err := PublishEvent(context.Background(), pub, Event{
		TenantID: "t1", EventType: "origin_change", Prefix: "192.0.2.0/24",
	}); err != nil {
		t.Fatal(err)
	}
	if len(pub.msgs) != 1 {
		t.Fatalf("published %d messages, want 1", len(pub.msgs))
	}
	if want := "probectl.tenant-one.bgp.events"; pub.msgs[0].topic != want {
		t.Fatalf("topic = %q, want %q", pub.msgs[0].topic, want)
	}
	if string(pub.msgs[0].key) != "t1" {
		t.Fatalf("key = %q, want tenant t1", pub.msgs[0].key)
	}
}

func TestBridgeFailsClosedOnInvalidTenantBusNamespace(t *testing.T) {
	withTestRouter(t, testIsolationRouter{targets: map[string]tenancy.Targets{
		"t1": {Model: tenancy.IsolationHybrid, BusNamespace: "bad.namespace"},
	}})
	pub := &capturePublisher{}

	err := PublishEvent(context.Background(), pub, Event{
		TenantID: "t1", EventType: "origin_change", Prefix: "192.0.2.0/24",
	})
	if err == nil || !strings.Contains(err.Error(), "route topic") {
		t.Fatalf("invalid namespace error = %v, want route-topic failure", err)
	}
	if len(pub.msgs) != 0 {
		t.Fatalf("published %d messages with an invalid tenant namespace; want fail-closed zero", len(pub.msgs))
	}
}

func TestBridgeFailsClosedOnMissingTenant(t *testing.T) {
	pub := &capturePublisher{}
	br := NewBridge(pub, discardLogger())

	// No tenant_id → the event must be skipped, never published (guardrail 1).
	line := `{"event_type":"possible_hijack","prefix":"192.0.2.0/24"}` + "\n"
	stats, err := br.Ingest(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Published != 0 || stats.Skipped != 1 {
		t.Fatalf("stats = %+v, want 0 published / 1 skipped", stats)
	}
	if len(pub.msgs) != 0 {
		t.Fatalf("a tenant-less event was published: %d messages", len(pub.msgs))
	}
}

func TestBridgeSkipsMalformedAndInvalidLines(t *testing.T) {
	pub := &capturePublisher{}
	br := NewBridge(pub, discardLogger())

	input := strings.Join([]string{
		"{ not json", // malformed
		originChange, // valid
		`{"tenant_id":"t1","event_type":"bogus","prefix":"192.0.2.0/24"}`, // unknown type
		"", // blank
	}, "\n") + "\n"

	stats, err := br.Ingest(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if stats.Published != 1 || stats.Skipped != 2 {
		t.Fatalf("stats = %+v, want 1 published / 2 skipped", stats)
	}
}

func TestBridgePublishErrorIsFatal(t *testing.T) {
	pub := &capturePublisher{err: errors.New("bus down")}
	br := NewBridge(pub, discardLogger())

	if _, err := br.Ingest(context.Background(), strings.NewReader(originChange+"\n")); err == nil {
		t.Fatal("expected the publish error to propagate")
	}
}

func TestBridgeDeliversOverMemoryBus(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()

	got := make(chan *bgpv1.BGPEvent, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = b.Subscribe(ctx, bus.BGPEventsTopic, "test", func(_ context.Context, m bus.Message) error {
			var ev bgpv1.BGPEvent
			if err := proto.Unmarshal(m.Value, &ev); err == nil {
				got <- &ev
			}
			return nil
		})
	}()
	time.Sleep(25 * time.Millisecond) // let the subscriber register (live pub/sub)

	br := NewBridge(b, discardLogger())
	if _, err := br.Ingest(ctx, strings.NewReader(originChange+"\n")); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-got:
		if ev.GetPrefix() != "192.0.2.0/24" || ev.GetTenantId() != "t1" {
			t.Errorf("delivered event = %q/%q", ev.GetTenantId(), ev.GetPrefix())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event did not land on the bus via the bridge")
	}
}
