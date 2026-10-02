// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

// ING-13: the OTLP receiver used to ack a push 200/OK and only THEN hand the
// batch to the bus. The default Kafka bus publishes asynchronously — Publish
// returns before the broker sees the record — so a batch over the broker's max
// message size was acked a success and dropped afterwards (silent loss), and a
// synchronous publish failure was mapped to a NON-retryable 500/Internal that
// the OTLP client would not retry. These tests pin the coupling: a batch the bus
// will not accept (oversize, or any publish failure) must return a RETRYABLE
// 503/UNAVAILABLE, never a 200 and never a non-retryable 500/Internal; a normal
// batch must still be acked 200/OK and reach the sink (telemetry loss is never
// silent, docs/guardrails.md G7-2).

// errBrokerRejects models the bus refusing a record (e.g. the broker rejecting
// an oversized message, or a shed at a full in-flight buffer).
var errBrokerRejects = errors.New("bus: broker rejected record (message too large)")

func postMetrics(t *testing.T, h http.Handler, token string, req *colmetricspb.ExportMetricsServiceRequest) int {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	body, _ := proto.Marshal(req)
	r, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// grpcExport drives the REAL OTLP/gRPC metrics service over bufconn with the
// authenticating interceptor — the production entry point — and returns the
// status code.
func grpcExport(t *testing.T, sink Sink, token string, req *colmetricspb.ExportMetricsServiceRequest) codes.Code {
	t.Helper()
	auth := NewTokenAuthenticator(map[string]string{"good": "tenant-a"})
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(authUnaryInterceptor(auth)))
	colmetricspb.RegisterMetricsServiceServer(srv, newMetricsService(sink))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
	_, err = colmetricspb.NewMetricsServiceClient(conn).Export(ctx, req)
	return status.Code(err)
}

func tenantAReq() *colmetricspb.ExportMetricsServiceRequest {
	return metricsRequest(resultResourceMetrics(&resultv1.Result{TenantId: "tenant-a"}))
}

// TestOTLPOversizeBatchIsRetryableNotAcked: a batch whose marshaled size exceeds
// the configured bus max is rejected BEFORE publish with a retryable status, and
// the publish function is never called — so the async producer can never accept
// it, ack 200, and have the broker drop it (ING-13: no silent loss).
func TestOTLPOversizeBatchIsRetryableNotAcked(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"good": "tenant-a"})

	// maxPublishBytes=8 is below any real marshaled metrics batch, so a normal
	// tenant-a push is "oversize" relative to the bus limit.
	var httpPublishCalls atomic.Int64
	httpSink := NewBusSinkWithLimit(8, func(context.Context, string, string, []byte) error {
		httpPublishCalls.Add(1)
		return nil // model Kafka's async Publish: it accepts (nil) and drops later.
	})
	h := MetricsHTTPHandler(auth, httpSink, 1<<20)
	if code := postMetrics(t, h, "good", tenantAReq()); code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP oversize: status = %d, want 503 (retryable, not acked)", code)
	}
	if n := httpPublishCalls.Load(); n != 0 {
		t.Fatalf("HTTP oversize: publish called %d times, want 0 (rejected before publish)", n)
	}

	var grpcPublishCalls atomic.Int64
	grpcSink := NewBusSinkWithLimit(8, func(context.Context, string, string, []byte) error {
		grpcPublishCalls.Add(1)
		return nil
	})
	if code := grpcExport(t, grpcSink, "good", tenantAReq()); code != codes.Unavailable {
		t.Fatalf("gRPC oversize: code = %v, want Unavailable", code)
	}
	if n := grpcPublishCalls.Load(); n != 0 {
		t.Fatalf("gRPC oversize: publish called %d times, want 0 (rejected before publish)", n)
	}
}

// TestOTLPPublishFailureIsRetryableNotAcked: a synchronous publish failure (the
// bus refusing the record) is surfaced as a RETRYABLE 503/UNAVAILABLE, not a
// 200 and not a non-retryable 500/Internal. This is the publish-result → ack
// coupling, and is the assertion that is RED before the fix (pre-fix: 500 /
// codes.Internal).
func TestOTLPPublishFailureIsRetryableNotAcked(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"good": "tenant-a"})

	failing := func(context.Context, string, string, []byte) error { return errBrokerRejects }

	h := MetricsHTTPHandler(auth, NewBusSink(failing), 1<<20)
	if code := postMetrics(t, h, "good", tenantAReq()); code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP publish failure: status = %d, want 503 (retryable); 200=silent loss, 500=non-retryable drop", code)
	}

	if code := grpcExport(t, NewBusSink(failing), "good", tenantAReq()); code != codes.Unavailable {
		t.Fatalf("gRPC publish failure: code = %v, want Unavailable", code)
	}
}

// TestOTLPNormalBatchStillAckedAndReachesSink: the happy path is unchanged — a
// batch under the limit is published and acked 200/OK, and the payload reaches
// the sink (no regression, no over-eager rejection).
func TestOTLPNormalBatchStillAckedAndReachesSink(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"good": "tenant-a"})

	var httpPayloadLen atomic.Int64
	httpSink := NewBusSinkWithLimit(1<<20, func(_ context.Context, _, _ string, payload []byte) error {
		httpPayloadLen.Store(int64(len(payload)))
		return nil
	})
	h := MetricsHTTPHandler(auth, httpSink, 1<<20)
	if code := postMetrics(t, h, "good", tenantAReq()); code != http.StatusOK {
		t.Fatalf("HTTP normal: status = %d, want 200", code)
	}
	if httpPayloadLen.Load() == 0 {
		t.Fatal("HTTP normal: sink never received the payload")
	}

	var grpcPayloadLen atomic.Int64
	grpcSink := NewBusSinkWithLimit(1<<20, func(_ context.Context, _, _ string, payload []byte) error {
		grpcPayloadLen.Store(int64(len(payload)))
		return nil
	})
	if code := grpcExport(t, grpcSink, "good", tenantAReq()); code != codes.OK {
		t.Fatalf("gRPC normal: code = %v, want OK", code)
	}
	if grpcPayloadLen.Load() == 0 {
		t.Fatal("gRPC normal: sink never received the payload")
	}
}
