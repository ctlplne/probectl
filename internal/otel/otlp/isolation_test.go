//go:build isolation

package otlp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"
)

// TENANT-105 (Sprint 6): the OTLP ingest surface in the cross-tenant suite.
// A push authenticated as tenant A whose payload names tenant B must be
// REJECTED (never re-attributed to B); an unscoped payload is stamped A; and
// the sink only ever sees the authenticated tenant. (The unit-level rejection
// is also covered in receiver_test.go; this ties OTLP into the end-to-end
// suite and asserts the DOWNSTREAM tenant handed to the sink.)
func TestOTLPIngestCrossTenantInjection(t *testing.T) {
	var (
		mu         sync.Mutex
		gotTenants []string
	)
	sink := SinkFunc(func(_ context.Context, tenant string, _ *colmetricspb.ExportMetricsServiceRequest) error {
		mu.Lock()
		gotTenants = append(gotTenants, tenant)
		mu.Unlock()
		return nil
	})
	h := MetricsHTTPHandler(NewTokenAuthenticator(map[string]string{"tok-a": "tenant-a"}), sink, 0)

	post := func(token string, body []byte) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/metrics", bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	marshal := func(r *resultv1.Result) []byte {
		b, _ := proto.Marshal(MetricsRequest(ResultResourceMetrics(r)))
		return b
	}

	// INJECTION: token scoped to A, payload claims B → forbidden, sink untouched.
	if code := post("tok-a", marshal(&resultv1.Result{TenantId: "tenant-b"})); code != http.StatusForbidden {
		t.Fatalf("cross-tenant OTLP push = %d, want 403", code)
	}
	// Matching tenant → accepted.
	if code := post("tok-a", marshal(&resultv1.Result{TenantId: "tenant-a"})); code != http.StatusOK {
		t.Fatalf("matching OTLP push = %d, want 200", code)
	}
	// No tenant in payload → stamped with the authenticated tenant, accepted.
	if code := post("tok-a", marshal(&resultv1.Result{})); code != http.StatusOK {
		t.Fatalf("unscoped OTLP push = %d, want 200", code)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotTenants) != 2 {
		t.Fatalf("sink saw %d pushes, want 2 (the injection must not reach it)", len(gotTenants))
	}
	for _, tn := range gotTenants {
		if tn != "tenant-a" {
			t.Fatalf("SINK LEAK: downstream tenant %q, want only tenant-a", tn)
		}
	}
}
