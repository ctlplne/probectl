// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pathstore

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

// TestLatestBoundsResponse is the RED-003a / SCALE-001 per-store acceptance
// test for pathstore: the LIVE read path (Latest → queryScoped → doQuery) must
// turn an oversized ClickHouse response into a bounded ErrResponseTooLarge
// rather than buffering the whole body (an all-tenant memory DoS). Pre-fix (a
// bare io.ReadAll(resp.Body)) this hangs/OOMs; post-fix it fails closed.
func TestLatestBoundsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if r.Method == http.MethodGet && strings.Contains(q, "SELECT path_id, target_ip") {
			w.WriteHeader(http.StatusOK)
			_, _ = io.CopyN(w, zeroReader{}, int64(chclient.MaxResponseBytes)+1)
			return
		}
		w.WriteHeader(http.StatusOK) // migrations
	}))
	defer srv.Close()

	c, err := NewClickHouse(srv.URL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, _, err = c.Latest(context.Background(), "tn-1", "10.0.0.1")
	if !errors.Is(err, chclient.ErrResponseTooLarge) {
		t.Fatalf("oversized ClickHouse response must fail closed with ErrResponseTooLarge, got %v", err)
	}
}
