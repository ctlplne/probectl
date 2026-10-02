// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7

import (
	"strings"
	"testing"
	"time"
)

// TestHTTP1StripsQueryStringSecrets is the ING-16 regression guard for the real
// L7 parse/emit entry point. A request target can carry secrets in its query
// string (?token=, ?api_key=, ?sig=). The parse path (Tracker detect+delegate
// -> http1 parser -> Call) produces the Resource the agent copies verbatim into
// the emitted L7Call.Resource, so the query-parameter VALUES must never leave
// the host: the path survives (useful for topology and RED metrics), the query
// does not. If a future change lets the query string back into Resource, this
// fails.
func TestHTTP1StripsQueryStringSecrets(t *testing.T) {
	secrets := []string{"s3cr3t-token", "AKIAEXAMPLEKEY", "9f8e7d"}
	req := "GET /v1/accounts?token=s3cr3t-token&api_key=AKIAEXAMPLEKEY&sig=9f8e7d HTTP/1.1\r\n" +
		"Host: app.example\r\nContent-Length: 0\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

	tr := NewTracker(80) // the real detect+delegate entry point
	t0 := time.Unix(10, 0)
	if c := tr.OnData(DataEvent{Kind: Request, Time: t0, Payload: []byte(req)}); len(c) != 0 {
		t.Fatalf("request alone emitted %d calls, want 0", len(c))
	}
	calls := tr.OnData(DataEvent{Kind: Response, Time: t0.Add(5 * time.Millisecond), Payload: []byte(resp)})
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	got := calls[0]

	// The path survives for usefulness...
	if got.Resource != "/v1/accounts" {
		t.Errorf("Resource = %q, want %q (path kept, query dropped)", got.Resource, "/v1/accounts")
	}
	// ...but no query marker and no query-parameter value may survive in it.
	if strings.ContainsRune(got.Resource, '?') {
		t.Errorf("emitted Resource still carries a query string: %q", got.Resource)
	}
	for _, s := range secrets {
		if strings.Contains(got.Resource, s) {
			t.Errorf("query-parameter secret %q leaked into emitted Resource %q", s, got.Resource)
		}
	}
	// The fix must not break ordinary call extraction.
	if got.Protocol != ProtoHTTP1 || got.Method != "GET" || got.Status != "200" || got.Error {
		t.Errorf("call extraction regressed: %+v", got)
	}
}
