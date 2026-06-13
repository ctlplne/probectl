// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"

	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
)

// ARCH-005: the OTel Collector's otlphttp exporter gzips by default. The
// receiver must transparently decompress a Content-Encoding: gzip body instead
// of rejecting it as an invalid payload.
func TestHTTPReceiverAcceptsGzip(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	var got int
	h := MetricsHTTPHandler(auth, SinkFunc(func(_ context.Context, _ string, _ *colmetricspb.ExportMetricsServiceRequest) error {
		got++
		return nil
	}), 1<<20)
	srv := httptest.NewServer(h)
	defer srv.Close()

	raw, _ := proto.Marshal(MetricsRequest(ResultResourceMetrics(&resultv1.Result{TenantId: "tenant-a"})))
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(raw)
	_ = gz.Close()

	r, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(buf.Bytes()))
	r.Header.Set("Authorization", "Bearer tok")
	r.Header.Set("Content-Type", "application/x-protobuf")
	r.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gzipped OTLP push: status = %d, want 200 (gzip not decompressed)", resp.StatusCode)
	}
	if got != 1 {
		t.Fatalf("sink consumed %d requests, want 1", got)
	}
}
