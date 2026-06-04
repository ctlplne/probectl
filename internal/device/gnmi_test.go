package device

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	gnmipb "github.com/imfeelingtheagi/probectl/internal/gen/gnmi"
)

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// captureEmitter collects emitted metrics across goroutines.
type captureEmitter struct {
	mu sync.Mutex
	ms []Metric
}

func (c *captureEmitter) Emit(_ context.Context, ms []Metric) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ms = append(c.ms, ms...)
	return nil
}

func (c *captureEmitter) snapshot() []Metric {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Metric(nil), c.ms...)
}

// mockGNMI is the in-process gNMI target: it validates the SubscriptionList,
// then streams canned OpenConfig notifications (the "mock gNMI target" the
// sprint's tests call for).
type mockGNMI struct {
	gnmipb.UnimplementedGNMIServer
	gotSubs chan *gnmipb.SubscriptionList
}

func (m *mockGNMI) Subscribe(stream gnmipb.GNMI_SubscribeServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	sl := req.GetSubscribe()
	select {
	case m.gotSubs <- sl:
	default:
	}

	ifElems := func(leafPath ...string) *gnmipb.Path {
		elems := []*gnmipb.PathElem{
			{Name: "interfaces"},
			{Name: "interface", Key: map[string]string{"name": "eth0"}},
			{Name: "state"},
		}
		for _, l := range leafPath {
			elems = append(elems, &gnmipb.PathElem{Name: l})
		}
		return &gnmipb.Path{Elem: elems}
	}
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano()

	// Counters notification (uint values) + an unmapped leaf that must be skipped.
	if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{
		Update: &gnmipb.Notification{
			Timestamp: now,
			Prefix:    &gnmipb.Path{Target: "core-sw1"},
			Update: []*gnmipb.Update{
				{Path: ifElems("counters", "in-octets"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 12345}}},
				{Path: ifElems("counters", "out-octets"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 67890}}},
				{Path: ifElems("counters", "carrier-transitions"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 9}}},
			},
		},
	}}); err != nil {
		return err
	}
	// Oper-status notification (string value -> 1/0).
	if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{
		Update: &gnmipb.Notification{
			Timestamp: now,
			Prefix:    &gnmipb.Path{Target: "core-sw1"},
			Update: []*gnmipb.Update{
				{Path: ifElems("oper-status"), Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "UP"}}},
			},
		},
	}}); err != nil {
		return err
	}
	// sync_response then end the stream (the client's reconnect loop takes over).
	_ = stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
	return nil
}

// TestGNMICollectorAgainstMockTarget runs the full client path — dial,
// subscribe, normalize, emit — against the in-process target over bufconn.
func TestGNMICollectorAgainstMockTarget(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	mock := &mockGNMI{gotSubs: make(chan *gnmipb.SubscriptionList, 1)}
	gnmipb.RegisterGNMIServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	em := &captureEmitter{}
	dev := DeviceConfig{
		Address: "192.0.2.50", Port: 9339, Transport: TransportGNMI, Credential: "lab",
		GNMI: GNMIConfig{
			Paths:          []string{"/interfaces/interface/state/counters", "/interfaces/interface/state/oper-status"},
			SampleInterval: time.Second,
			Plaintext:      true, // bufconn carries no TLS; production defaults to verified TLS
		},
	}
	c := &gnmiCollector{
		dev: dev, cred: Credential{Username: "probe", Password: "pw"},
		tenant: "t-a", agent: "agent-1", emit: em,
		log:            slog.Default(),
		targetOverride: "passthrough:///bufnet",
		dialOpts: []grpc.DialOption{grpc.WithContextDialer(
			func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) })},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.run(ctx)

	// The server saw our subscription list...
	select {
	case sl := <-mock.gotSubs:
		if len(sl.GetSubscription()) != 2 || sl.GetMode() != gnmipb.SubscriptionList_STREAM {
			t.Fatalf("subscription list = %+v", sl)
		}
		if sl.GetSubscription()[0].GetMode() != gnmipb.SubscriptionMode_SAMPLE {
			t.Fatalf("subscription mode = %v, want SAMPLE", sl.GetSubscription()[0].GetMode())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server never received a subscription")
	}

	// ...and the collector normalized the notifications.
	deadline := time.Now().Add(3 * time.Second)
	for {
		ms := em.snapshot()
		if len(ms) >= 3 {
			byName := map[string]Metric{}
			for _, m := range ms {
				byName[m.Name] = m
				if m.TenantID != "t-a" || m.Source != SourceGNMI || m.Device != "192.0.2.50" {
					t.Fatalf("identity = %+v", m)
				}
				if m.IfName != "eth0" {
					t.Fatalf("ifName from path key = %q", m.IfName)
				}
				if m.DeviceName != "core-sw1" {
					t.Fatalf("device name from prefix target = %q", m.DeviceName)
				}
			}
			if byName[MetricIfInOctets].Value != 12345 || byName[MetricIfOutOctets].Value != 67890 {
				t.Fatalf("counters = %+v", byName)
			}
			if byName[MetricIfOperStatus].Value != 1 {
				t.Fatalf("oper-status UP -> 1, got %+v", byName[MetricIfOperStatus])
			}
			for _, m := range ms {
				if m.Value == 9 {
					t.Fatal("unmapped leaf (carrier-transitions) leaked through")
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out; metrics = %+v", em.snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTypedValueCoercion pins the TypedValue variants the collector maps.
func TestTypedValueCoercion(t *testing.T) {
	cases := []struct {
		leaf string
		tv   *gnmipb.TypedValue
		want float64
		ok   bool
	}{
		{"in-octets", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_UintVal{UintVal: 5}}, 5, true},
		{"in-octets", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_IntVal{IntVal: -2}}, -2, true},
		{"in-octets", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: 1.5}}, 1.5, true},
		{"oper-status", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "up"}}, 1, true},
		{"oper-status", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "DOWN"}}, 0, true},
		{"in-octets", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "n/a"}}, 0, false},
		{"in-octets", nil, 0, false},
	}
	for _, c := range cases {
		got, ok := typedValueFloat(c.leaf, c.tv)
		if got != c.want || ok != c.ok {
			t.Errorf("typedValueFloat(%s, %v) = %v,%v want %v,%v", c.leaf, c.tv, got, ok, c.want, c.ok)
		}
	}
}

// TestParsePath covers the small OpenConfig path parser incl. [key=value].
func TestParsePath(t *testing.T) {
	p := parsePath("/interfaces/interface[name=eth0]/state/counters")
	if len(p.Elem) != 4 || p.Elem[1].Name != "interface" || p.Elem[1].Key["name"] != "eth0" {
		t.Fatalf("parsed = %+v", p)
	}
	if got := pathKey(p.Elem, "interface", "name"); got != "eth0" {
		t.Fatalf("pathKey = %q", got)
	}
}
