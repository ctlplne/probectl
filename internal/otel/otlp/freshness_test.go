// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

func TestFreshnessVerifierHTTPRejectsMissingReplayStaleAndTamperedEnvelopes(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, crypto.KeySize)
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	freshness := NewFreshnessVerifier(key, time.Minute)
	freshness.now = func() time.Time { return now }

	accepted := 0
	h := MetricsHTTPHandlerWithFreshness(
		NewTokenAuthenticator(map[string]string{"tok": "tenant-a"}),
		SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error {
			accepted++
			return nil
		}),
		1<<20,
		freshness,
	)

	body, err := proto.Marshal(MetricsRequest(ResultResourceMetrics(&resultv1.Result{TenantId: "tenant-a"})))
	if err != nil {
		t.Fatal(err)
	}
	post := func(headers http.Header, body []byte) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/x-protobuf")
		for k, vals := range headers {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post(nil, body); code != http.StatusUnauthorized {
		t.Fatalf("missing freshness = %d, want 401", code)
	}

	good := FreshnessHTTPHeaders(key, now, "nonce-1", http.MethodPost, "/v1/metrics", body)
	if code := post(good, body); code != http.StatusOK {
		t.Fatalf("fresh request = %d, want 200", code)
	}
	if code := post(good, body); code != http.StatusUnauthorized {
		t.Fatalf("replayed nonce = %d, want 401", code)
	}

	stale := FreshnessHTTPHeaders(key, now.Add(-2*time.Minute), "nonce-2", http.MethodPost, "/v1/metrics", body)
	if code := post(stale, body); code != http.StatusUnauthorized {
		t.Fatalf("stale envelope = %d, want 401", code)
	}

	tamperedBody := append([]byte(nil), body...)
	tamperedBody[len(tamperedBody)-1] ^= 0xff
	tampered := FreshnessHTTPHeaders(key, now, "nonce-3", http.MethodPost, "/v1/metrics", body)
	if code := post(tampered, tamperedBody); code != http.StatusUnauthorized {
		t.Fatalf("tampered body = %d, want 401", code)
	}

	if accepted != 1 {
		t.Fatalf("accepted requests = %d, want exactly one fresh request", accepted)
	}
}

func TestFreshnessVerifierGRPCUsesMethodBodyAndNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, crypto.KeySize)
	now := time.Date(2026, 6, 19, 12, 30, 0, 0, time.UTC)
	method := "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
	req := MetricsRequest()
	freshness := NewFreshnessVerifier(key, time.Minute)
	freshness.now = func() time.Time { return now }

	md, err := FreshnessGRPCMetadata(key, now, "grpc-nonce-1", method, req)
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if err := freshness.VerifyGRPC(ctx, method, "tenant-a", req); err != nil {
		t.Fatalf("fresh grpc envelope refused: %v", err)
	}
	if err := freshness.VerifyGRPC(ctx, method, "tenant-a", req); err == nil {
		t.Fatal("replayed grpc nonce accepted")
	}

	md, err = FreshnessGRPCMetadata(key, now, "grpc-nonce-2", method, req)
	if err != nil {
		t.Fatal(err)
	}
	ctx = metadata.NewIncomingContext(context.Background(), md)
	if err := freshness.VerifyGRPC(ctx, method+"Typo", "tenant-a", req); err == nil {
		t.Fatal("method-tampered grpc envelope accepted")
	}
}
