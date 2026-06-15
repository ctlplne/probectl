// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpfstore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/store/chclient"
)

// zeroReader is an unbounded NUL source with no backing buffer, so the handler
// can stream a body larger than the read limit without allocating it.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestTopEdgesBoundsResponse is the RED-003a / SCALE-001 per-store acceptance
// test for ebpfstore: the LIVE read path (TopEdges → queryAt) must turn an
// oversized ClickHouse response into a bounded ErrResponseTooLarge rather than
// buffering the whole body (an all-tenant memory DoS). Pre-fix (a bare
// io.ReadAll(resp.Body)) this hangs/OOMs; post-fix it fails closed.
func TestTopEdgesBoundsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if r.Method == http.MethodGet && strings.Contains(q, "SELECT") && strings.Contains(q, "src_workload") {
			w.WriteHeader(http.StatusOK)
			_, _ = io.CopyN(w, zeroReader{}, int64(chclient.MaxResponseBytes)+1)
			return
		}
		w.WriteHeader(http.StatusOK) // migrations
	}))
	defer srv.Close()

	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = c.TopEdges(context.Background(), "tn-1", EdgeQuery{Limit: 10})
	if !errors.Is(err, chclient.ErrResponseTooLarge) {
		t.Fatalf("oversized ClickHouse response must fail closed with ErrResponseTooLarge, got %v", err)
	}
}
