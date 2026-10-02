// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"testing"

	"github.com/ctlplne/probectl/internal/ebpf/l7"
)

// TestRedactPayloadZeroesRequestQueryString is the ING-16 capture-boundary
// guard. Under the default "headers" mode the request LINE survives as protocol
// metadata, but a query string in the request target can carry secrets
// (?token=, ?api_key=, ?sig=). Those values must be zeroed in the single
// retained copy just like sensitive header values are (the request-line
// companion to redactHeaderValues): the path, the '?' marker, and the line
// framing survive so the chunk still parses, and the parsed Resource keeps the
// path only. If a future change lets a query-parameter value transit the
// boundary, this fails.
func TestRedactPayloadZeroesRequestQueryString(t *testing.T) {
	req := []byte("GET /v1/accounts?token=s3cr3t-token&api_key=AKIAEXAMPLEKEY HTTP/1.1\r\n" +
		"Host: app.example\r\n" +
		"Content-Length: 0\r\n\r\n")
	red := redactPayload(append([]byte(nil), req...), RedactHeaders)

	if len(red) != len(req) {
		t.Fatalf("length must be preserved for framing: %d != %d", len(red), len(req))
	}
	for _, secret := range [][]byte{
		[]byte("s3cr3t-token"),
		[]byte("AKIAEXAMPLEKEY"),
		[]byte("token=s3cr3t-token"),
	} {
		if bytes.Contains(red, secret) {
			t.Fatalf("query-string secret leaked through headers-mode redaction: %q in %q", secret, red)
		}
	}
	// The path, the '?' marker, the request-line tail, and benign headers survive.
	for _, keep := range [][]byte{
		[]byte("GET /v1/accounts?"),
		[]byte(" HTTP/1.1"),
		[]byte("Host: app.example"),
	} {
		if !bytes.Contains(red, keep) {
			t.Fatalf("metadata that must survive was clobbered: %q missing from %q", keep, red)
		}
	}

	// The redacted stream still parses, and the emitted Resource keeps only the path.
	p := l7.NewTracker(443)
	p.OnData(l7.DataEvent{Kind: l7.Request, Payload: red})
	calls := p.OnData(l7.DataEvent{Kind: l7.Response, Payload: []byte("HTTP/1.1 200 OK\r\n\r\n")})
	if len(calls) != 1 || calls[0].Method != "GET" || calls[0].Resource != "/v1/accounts" {
		t.Fatalf("redacted stream must still parse to a path-only resource: %+v", calls)
	}

	// Full mode (consented debugging) is unchanged: the target is left intact.
	if got := redactPayload(append([]byte(nil), req...), RedactFull); !bytes.Contains(got, []byte("token=s3cr3t-token")) {
		t.Fatal("full mode must not redact the request target")
	}
}
