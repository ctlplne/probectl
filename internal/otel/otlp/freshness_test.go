// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
)

const testedFreshnessNonceLimit = 128

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

	body, err := proto.Marshal(metricsRequest(resultResourceMetrics(&resultv1.Result{TenantId: "tenant-a"})))
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

	good := freshnessHTTPHeaders(key, now, "nonce-1", http.MethodPost, "/v1/metrics", body)
	if code := post(good, body); code != http.StatusOK {
		t.Fatalf("fresh request = %d, want 200", code)
	}
	if code := post(good, body); code != http.StatusUnauthorized {
		t.Fatalf("replayed nonce = %d, want 401", code)
	}

	stale := freshnessHTTPHeaders(key, now.Add(-2*time.Minute), "nonce-2", http.MethodPost, "/v1/metrics", body)
	if code := post(stale, body); code != http.StatusUnauthorized {
		t.Fatalf("stale envelope = %d, want 401", code)
	}

	tamperedBody := append([]byte(nil), body...)
	tamperedBody[len(tamperedBody)-1] ^= 0xff
	tampered := freshnessHTTPHeaders(key, now, "nonce-3", http.MethodPost, "/v1/metrics", body)
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
	req := metricsRequest()
	freshness := NewFreshnessVerifier(key, time.Minute)
	freshness.now = func() time.Time { return now }

	md, err := freshnessGRPCMetadata(key, now, "grpc-nonce-1", method, req)
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

	md, err = freshnessGRPCMetadata(key, now, "grpc-nonce-2", method, req)
	if err != nil {
		t.Fatal(err)
	}
	ctx = metadata.NewIncomingContext(context.Background(), md)
	if err := freshness.VerifyGRPC(ctx, method+"Typo", "tenant-a", req); err == nil {
		t.Fatal("method-tampered grpc envelope accepted")
	}
}

func TestFreshnessNonceByteBoundHTTPAndGRPC(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, crypto.KeySize)
	now := time.Date(2026, 6, 19, 13, 0, 0, 0, time.UTC)
	method := "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
	grpcRequest := metricsRequest()
	httpBody := []byte("bounded OTLP body")

	for _, tc := range []struct {
		name    string
		nonce   string
		wantErr bool
	}{
		{name: "exact_max", nonce: strings.Repeat("n", testedFreshnessNonceLimit)},
		{name: "one_past", nonce: strings.Repeat("n", testedFreshnessNonceLimit+1), wantErr: true},
	} {
		t.Run(tc.name+"/http", func(t *testing.T) {
			freshness := NewFreshnessVerifier(key, time.Minute)
			freshness.now = func() time.Time { return now }
			req := httptest.NewRequest(http.MethodPost, "/v1/metrics", nil)
			req.Header = freshnessHTTPHeaders(key, now, tc.nonce, http.MethodPost, req.URL.Path, httpBody)

			err := freshness.VerifyHTTP(req, "tenant-a", httpBody)
			if tc.wantErr && err == nil {
				t.Fatal("oversized HTTP freshness nonce accepted")
			}
			if tc.wantErr && !strings.Contains(err.Error(), "exceeds 128 bytes") {
				t.Fatalf("oversized HTTP freshness nonce error = %q, want byte-limit error", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("maximum-size HTTP freshness nonce refused: %v", err)
			}
		})

		t.Run(tc.name+"/grpc", func(t *testing.T) {
			freshness := NewFreshnessVerifier(key, time.Minute)
			freshness.now = func() time.Time { return now }
			md, err := freshnessGRPCMetadata(key, now, tc.nonce, method, grpcRequest)
			if err != nil {
				t.Fatal(err)
			}
			ctx := metadata.NewIncomingContext(context.Background(), md)

			err = freshness.VerifyGRPC(ctx, method, "tenant-a", grpcRequest)
			if tc.wantErr && err == nil {
				t.Fatal("oversized gRPC freshness nonce accepted")
			}
			if tc.wantErr && !strings.Contains(err.Error(), "exceeds 128 bytes") {
				t.Fatalf("oversized gRPC freshness nonce error = %q, want byte-limit error", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("maximum-size gRPC freshness nonce refused: %v", err)
			}
		})
	}
}

func TestFreshnessOversizedNonceDoesNotEnterReplayCache(t *testing.T) {
	key := bytes.Repeat([]byte{0x53}, crypto.KeySize)
	now := time.Date(2026, 6, 19, 13, 30, 0, 0, time.UTC)
	body := []byte("replay retention body")
	freshness := NewFreshnessVerifier(key, time.Minute)
	freshness.now = func() time.Time { return now }

	verify := func(nonce string) error {
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", nil)
		req.Header = freshnessHTTPHeaders(key, now, nonce, http.MethodPost, req.URL.Path, body)
		return freshness.VerifyHTTP(req, "tenant-a", body)
	}

	oversized := strings.Repeat("o", testedFreshnessNonceLimit+1)
	if err := verify(oversized); err == nil {
		t.Error("oversized freshness nonce accepted")
	} else if !strings.Contains(err.Error(), "exceeds 128 bytes") {
		t.Errorf("oversized freshness nonce error = %q, want byte-limit error", err)
	}

	freshness.mu.Lock()
	retainedAfterOversized := len(freshness.seen)
	freshness.mu.Unlock()
	if retainedAfterOversized != 0 {
		t.Errorf("replay scopes after oversized nonce = %d, want 0", retainedAfterOversized)
	}

	maximum := strings.Repeat("m", testedFreshnessNonceLimit)
	if err := verify(maximum); err != nil {
		t.Fatalf("maximum-size freshness nonce refused: %v", err)
	}

	freshness.mu.Lock()
	tenantSeen := freshness.seen["tenant-a"]
	_, retainedMaximum := tenantSeen[maximum]
	_, retainedOversized := tenantSeen[oversized]
	retainedCount := len(tenantSeen)
	freshness.mu.Unlock()
	if !retainedMaximum {
		t.Error("accepted maximum-size freshness nonce was not retained")
	}
	if retainedOversized {
		t.Error("rejected oversized freshness nonce was retained")
	}
	if retainedCount != 1 {
		t.Errorf("retained freshness nonces = %d, want 1", retainedCount)
	}
}
