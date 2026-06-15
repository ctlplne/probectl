// SPDX-License-Identifier: LicenseRef-probectl-TBD

package flowstore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/chclient"
)

// zeroReader is an unbounded source of NUL bytes with no backing buffer, so the
// httptest handler can stream a body larger than the read limit without
// allocating it (the server-side analog of a runaway/malicious ClickHouse
// response).
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestTopTalkersBoundsResponse is the RED-003a / SCALE-001 per-store acceptance
// test for flowstore: the LIVE read path (TopTalkers → queryScoped → doQuery)
// must turn an oversized ClickHouse response into a bounded ErrResponseTooLarge
// error rather than buffering the whole body. Pre-fix (a bare
// io.ReadAll(resp.Body)) this hangs/OOMs on an oversized body; post-fix it
// fails closed. Migration DDL (POST) is answered 200 so NewClickHouse succeeds;
// only the SELECT read streams the oversized body.
func TestTopTalkersBoundsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if r.Method == http.MethodGet && strings.Contains(q, "SELECT") && strings.Contains(q, "sum(bytes_scaled)") {
			// Stream just over the limit; the bounded reader stops early and the
			// connection closes, so a partial write (broken pipe) is expected.
			w.WriteHeader(http.StatusOK)
			_, _ = io.CopyN(w, zeroReader{}, int64(chclient.MaxResponseBytes)+1)
			return
		}
		w.WriteHeader(http.StatusOK) // migrations / counts
	}))
	defer srv.Close()

	c, err := NewClickHouse(srv.URL, 0)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = c.TopTalkers(context.Background(), TopQuery{
		TenantID: "tn-1", By: BySrc, Limit: 10, Window: time.Hour, Now: time.Now(),
	})
	if !errors.Is(err, chclient.ErrResponseTooLarge) {
		t.Fatalf("oversized ClickHouse response must fail closed with ErrResponseTooLarge, got %v", err)
	}
}
