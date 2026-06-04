package otlp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// newBufconnReceiver starts an in-process OTLP/gRPC MetricsService (auth
// interceptor + sink) over bufconn and returns its listener.
func newBufconnReceiver(t *testing.T, auth Authenticator, sink Sink) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(authUnaryInterceptor(auth)))
	colmetricspb.RegisterMetricsServiceServer(srv, newMetricsService(sink))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis
}

func TestGRPCExporterRequiresTLS(t *testing.T) {
	if _, err := NewGRPCExporter(ExporterConfig{Endpoint: "collector:4317"}); err == nil {
		t.Error("expected NewGRPCExporter to require TLS (or Insecure)")
	}
}

func TestHTTPExporterErrors(t *testing.T) {
	if _, err := NewHTTPExporter(ExporterConfig{}); err == nil {
		t.Error("empty endpoint should error")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	exp, err := NewHTTPExporter(ExporterConfig{Endpoint: srv.URL, Token: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.ExportMetrics(context.Background(), MetricsRequest()); err == nil {
		t.Error("a non-200 response should surface as an error")
	}
}

// TestRoundTripHTTP exports a probectl Result as OTLP/HTTP through the receiver and
// asserts the tenant + canonical resource attributes survive.
func TestRoundTripHTTP(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	type capture struct {
		tenant string
		req    *colmetricspb.ExportMetricsServiceRequest
	}
	ch := make(chan capture, 1)
	srv := httptest.NewServer(MetricsHTTPHandler(auth, SinkFunc(func(_ context.Context, tenant string, req *colmetricspb.ExportMetricsServiceRequest) error {
		ch <- capture{tenant, req}
		return nil
	}), 1<<20))
	defer srv.Close()

	exp, err := NewHTTPExporter(ExporterConfig{Endpoint: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	r := &resultv1.Result{TenantId: "tenant-a", AgentId: "a1", CanaryType: "icmp", Success: true, DurationNano: 1234, Metrics: map[string]float64{"rtt.avg.ms": 9}}
	if err := exp.ExportMetrics(context.Background(), MetricsRequest(ResultResourceMetrics(r))); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-ch:
		if got.tenant != "tenant-a" {
			t.Errorf("tenant = %q, want tenant-a", got.tenant)
		}
		if len(got.req.GetResourceMetrics()) != 1 {
			t.Fatalf("resource metrics = %d, want 1", len(got.req.GetResourceMetrics()))
		}
		attrs := resourceAttrs(got.req.GetResourceMetrics()[0])
		if attrs["probectl.tenant.id"] != "tenant-a" || attrs["probectl.canary.type"] != "icmp" {
			t.Errorf("round-trip attrs = %v", attrs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the receiver sink")
	}
}

// TestRoundTripGRPC exports over OTLP/gRPC (bufconn) through the authenticating,
// tenant-scoping receiver.
func TestRoundTripGRPC(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	ch := make(chan string, 1)
	lis := newBufconnReceiver(t, auth, SinkFunc(func(_ context.Context, tenant string, _ *colmetricspb.ExportMetricsServiceRequest) error {
		ch <- tenant
		return nil
	}))

	exp, err := NewGRPCExporter(ExporterConfig{Endpoint: "passthrough:///bufnet", Token: "tok", Insecure: true},
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()

	if err := exp.ExportMetrics(context.Background(), MetricsRequest(ResultResourceMetrics(&resultv1.Result{TenantId: "tenant-a"}))); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got != "tenant-a" {
			t.Errorf("tenant = %q, want tenant-a", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the receiver sink")
	}
}
