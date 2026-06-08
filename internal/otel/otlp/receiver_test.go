package otlp

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

func TestGRPCServerRequiresTLS(t *testing.T) {
	if _, err := NewGRPCServer(nil, NewTokenAuthenticator(nil), testSinks(SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error { return nil })), 0); err == nil {
		t.Error("expected NewGRPCServer to reject a nil TLS config (TLS-only)")
	}
}

func TestGRPCReceiverAuthAndTenantScope(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"good": "tenant-a"})
	var (
		mu  sync.Mutex
		got []string
	)
	sink := SinkFunc(func(_ context.Context, tenant string, _ *colmetricspb.ExportMetricsServiceRequest) error {
		mu.Lock()
		got = append(got, tenant)
		mu.Unlock()
		return nil
	})

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(authUnaryInterceptor(auth)))
	colmetricspb.RegisterMetricsServiceServer(srv, newMetricsService(sink))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := colmetricspb.NewMetricsServiceClient(conn)

	withTok := func(tok string) context.Context {
		if tok == "" {
			return context.Background()
		}
		return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+tok)
	}

	if _, err := client.Export(withTok(""), MetricsRequest()); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no token: code = %v, want Unauthenticated", status.Code(err))
	}
	if _, err := client.Export(withTok("nope"), MetricsRequest()); status.Code(err) != codes.Unauthenticated {
		t.Errorf("bad token: code = %v, want Unauthenticated", status.Code(err))
	}
	bad := MetricsRequest(ResultResourceMetrics(&resultv1.Result{TenantId: "tenant-b"}))
	if _, err := client.Export(withTok("good"), bad); status.Code(err) != codes.PermissionDenied {
		t.Errorf("out-of-tenant: code = %v, want PermissionDenied", status.Code(err))
	}
	ok := MetricsRequest(ResultResourceMetrics(&resultv1.Result{TenantId: "tenant-a"}))
	if _, err := client.Export(withTok("good"), ok); err != nil {
		t.Errorf("valid push: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "tenant-a" {
		t.Errorf("sink received %v, want [tenant-a]", got)
	}
}

func TestHTTPReceiverAuthAndTenantScope(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	var captured string
	h := MetricsHTTPHandler(auth, SinkFunc(func(_ context.Context, tenant string, _ *colmetricspb.ExportMetricsServiceRequest) error {
		captured = tenant
		return nil
	}), 1<<20)
	srv := httptest.NewServer(h)
	defer srv.Close()

	post := func(token string, req *colmetricspb.ExportMetricsServiceRequest) int {
		body, _ := proto.Marshal(req)
		r, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Content-Type", "application/x-protobuf")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if code := post("", MetricsRequest()); code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", code)
	}
	if code := post("tok", MetricsRequest(ResultResourceMetrics(&resultv1.Result{TenantId: "tenant-b"}))); code != http.StatusForbidden {
		t.Errorf("out-of-tenant: status = %d, want 403", code)
	}
	if code := post("tok", MetricsRequest(ResultResourceMetrics(&resultv1.Result{TenantId: "tenant-a"}))); code != http.StatusOK {
		t.Errorf("valid push: status = %d, want 200", code)
	}
	if captured != "tenant-a" {
		t.Errorf("sink tenant = %q, want tenant-a", captured)
	}
}

func TestNewGRPCServerHappyPath(t *testing.T) {
	srv, err := NewGRPCServer(
		&tls.Config{MinVersion: tls.VersionTLS12},
		NewTokenAuthenticator(map[string]string{"t": "x"}),
		testSinks(SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error { return nil })),
		1<<20,
	)
	if err != nil || srv == nil {
		t.Fatalf("NewGRPCServer: srv=%v err=%v", srv, err)
	}
	srv.Stop()
}

func TestExportMissingTenantContextRejected(t *testing.T) {
	svc := newMetricsService(SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error { return nil }))
	// Calling Export without the interceptor (no tenant on ctx) must fail closed.
	if _, err := svc.Export(context.Background(), MetricsRequest()); status.Code(err) != codes.Unauthenticated {
		t.Errorf("missing tenant: code = %v, want Unauthenticated", status.Code(err))
	}
}
