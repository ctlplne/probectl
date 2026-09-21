// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"crypto/tls"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	probectlcrypto "github.com/ctlplne/probectl/internal/crypto"
	gnmipb "github.com/ctlplne/probectl/internal/gen/gnmi"
)

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestGNMIPlaintextRejected(t *testing.T) {
	dev := Target{
		Address: "192.0.2.50", Transport: TransportGNMI, Credential: "device-login",
		GNMI: GNMIConfig{Plaintext: true},
	}
	t.Run("configuration", func(t *testing.T) {
		cfg := &Config{TenantID: "tenant-a", Devices: []Target{dev}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "plaintext") {
			t.Fatalf("plaintext gNMI configuration error = %v, want explicit rejection", err)
		}
	})
	t.Run("transport", func(t *testing.T) {
		collector := &gnmiCollector{dev: dev, log: slog.Default()}
		if _, err := collector.transport(); err == nil || !strings.Contains(err.Error(), "plaintext") {
			t.Fatalf("plaintext gNMI transport error = %v, want rejection before dial", err)
		}
	})
}

func startTLSGNMITarget(t *testing.T, service gnmipb.GNMIServer) (*bufconn.Listener, string) {
	t.Helper()
	ca, err := probectlcrypto.GenerateCA("gnmi-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("bufnet", []string{"bufnet"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})))
	gnmipb.RegisterGNMIServer(srv, service)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis, caFile
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

type oversizedGNMI struct {
	gnmipb.UnimplementedGNMIServer
}

func (oversizedGNMI) Subscribe(stream gnmipb.GNMI_SubscribeServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	big := strings.Repeat("x", 4096)
	return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{
		Update: &gnmipb.Notification{
			Timestamp: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC).UnixNano(),
			Prefix:    &gnmipb.Path{Target: big},
			Update: []*gnmipb.Update{
				{
					Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{
						{Name: "interfaces"},
						{Name: "interface", Key: map[string]string{"name": "eth0"}},
						{Name: "state"},
						{Name: "counters"},
						{Name: "in-octets"},
					}},
					Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: big}},
				},
			},
		},
	}})
}

// TestGNMITLSCollectorAgainstMockTarget runs the full verified-TLS client path
// — dial, subscribe, normalize, emit — against the in-process target over
// bufconn.
func TestGNMITLSCollectorAgainstMockTarget(t *testing.T) {
	mock := &mockGNMI{gotSubs: make(chan *gnmipb.SubscriptionList, 1)}
	lis, caFile := startTLSGNMITarget(t, mock)

	em := &captureEmitter{}
	dev := Target{
		Address: "192.0.2.50", Port: 9339, Transport: TransportGNMI, Credential: "lab",
		GNMI: GNMIConfig{
			Paths:          []string{"/interfaces/interface/state/counters", "/interfaces/interface/state/oper-status"},
			SampleInterval: time.Second,
			CAFile:         caFile,
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

func TestGNMICollectorRejectsOversizedResponse(t *testing.T) {
	lis, caFile := startTLSGNMITarget(t, oversizedGNMI{})

	dev := Target{
		Address: "192.0.2.51", Port: 9339, Transport: TransportGNMI,
		GNMI: GNMIConfig{
			Paths:          []string{"/interfaces/interface/state/counters"},
			SampleInterval: time.Second,
			CAFile:         caFile,
		},
	}
	c := &gnmiCollector{
		dev: dev, tenant: "t-a", agent: "agent-1", emit: &captureEmitter{},
		log:            slog.Default(),
		targetOverride: "passthrough:///bufnet",
		maxRecvMsgSize: 512,
		dialOpts: []grpc.DialOption{grpc.WithContextDialer(
			func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) })},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := c.streamOnce(ctx)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("streamOnce error = %v, want ResourceExhausted from explicit receive cap", err)
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
		{"in-octets", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: math.Inf(1)}}, 0, false},
		{"in-octets", &gnmipb.TypedValue{Value: &gnmipb.TypedValue_DoubleVal{DoubleVal: math.NaN()}}, 0, false},
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
