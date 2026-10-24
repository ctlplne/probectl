// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ebpf/l7"
)

// The D-43 metadata mode at the capture boundary: the request line (query
// zeroed) and the framing header values survive the parse window; every other
// header value and the whole body are zeroed in place.
func TestMetadataRedactionZeroesEveryNonFramingHeaderValue(t *testing.T) {
	req := []byte("POST /patients/48213/notes?token=QUERYSECRET HTTP/1.1\r\n" +
		"Host: records.internal\r\n" +
		"Authorization: Bearer CREDSECRET\r\n" +
		"X-Forwarded-For: 203.0.113.9\r\n" +
		"Referer: https://portal/patient/48213\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 22\r\n\r\n" +
		`{"diagnosis":"BODYPII"}`)
	out := redactPayloadWithPolicy(append([]byte(nil), req...), RedactMetadata, headerValuePolicy{hashAllValues: true})
	if len(out) != len(req) {
		t.Fatalf("length changed: %d != %d (framing must stay parseable)", len(out), len(req))
	}
	for _, leak := range []string{"QUERYSECRET", "CREDSECRET", "records.internal", "203.0.113.9", "portal", "application/json", "BODYPII", "sha256:"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Errorf("metadata mode kept %q in the parse window", leak)
		}
	}
	for _, keep := range []string{"POST /patients/48213/notes?", "Content-Length: 22", "Host:", "Authorization:"} {
		if !bytes.Contains(out, []byte(keep)) {
			t.Errorf("metadata mode lost %q (request line, framing and header names survive)", keep)
		}
	}
}

func TestMetadataStreamZeroesBodyContinuations(t *testing.T) {
	streams := newStreamRedactor()
	key := streamKey{pid: 1, conn: 7}
	head := []byte("POST /a HTTP/1.1\r\nX-Note: v\r\nContent-Length: 64\r\n\r\n")
	streams.redact(key, append([]byte(nil), head...), RedactMetadata, headerValuePolicy{})
	body := []byte("CONTINUATIONSECRET\r\n\r\nmore body that looks like a header terminator")
	out := streams.redact(key, append([]byte(nil), body...), RedactMetadata, headerValuePolicy{})
	if !bytes.Equal(out, make([]byte, len(body))) {
		t.Fatalf("metadata body continuation survived: %q", out)
	}
}

func TestKernelWindowForMetadata(t *testing.T) {
	if w := kernelWindowFor(RedactMetadata, 0); w != defaultKernelWindow {
		t.Fatalf("metadata kernel window = %d, want the header window %d", w, defaultKernelWindow)
	}
}

// metadataRun drives one HTTP/1 exchange through the agent at mode and returns
// the emitted record.
func metadataRun(t *testing.T, mode string) L7Record {
	t.Helper()
	t0 := time.Unix(0, 0)
	src := Endpoint{Workload: "portal"}
	dst := Endpoint{Workload: "records", Port: 8443}
	req := "GET /contracts/W56HZV-23-C-0123/drawings?sig=QUERYSECRET HTTP/1.1\r\nAuthorization: Bearer CREDSECRET\r\nContent-Length: 0\r\n\r\n"
	l7src := &sliceL7Source{events: []L7Event{
		{ConnID: 1, TenantID: "t1", Source: src, Destination: dst, Data: l7.DataEvent{Kind: l7.Request, Time: t0, Payload: []byte(req)}},
		{ConnID: 1, Data: l7.DataEvent{Kind: l7.Response, Time: t0.Add(5 * time.Millisecond), Payload: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")}},
	}}
	em := &captureEmitter{}
	cfg := &Config{TenantID: "t1", Host: "n", FlushInterval: time.Hour, L7CaptureRedaction: mode}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &sliceSource{}, NopEnricher{}, em)
	a.l7source = l7src
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(em.l7) != 1 {
		t.Fatalf("emitted %d calls, want 1", len(em.l7))
	}
	return em.l7[0]
}

func TestAgentEmitsTemplatedRouteUnderMetadata(t *testing.T) {
	r := metadataRun(t, RedactMetadata)
	if r.Call.Resource != "/contracts/{id}/drawings" || r.Call.Method != "GET" || r.Call.Status != "200" {
		t.Fatalf("metadata call = %+v, want the templated route", r.Call)
	}
	// The default (empty) mode is metadata too.
	if d := metadataRun(t, ""); d.Call.Resource != "/contracts/{id}/drawings" {
		t.Fatalf("default-mode call = %+v, want the templated route", d.Call)
	}
	// headers keeps the literal segments (an opt-in), never the query.
	if h := metadataRun(t, RedactHeaders); h.Call.Resource != "/contracts/W56HZV-23-C-0123/drawings" {
		t.Fatalf("headers call = %+v", h.Call)
	}
}

// The fixture replay is exempt from the consent gate (it is not live capture)
// but not from the redaction boundary.
func TestFixtureReplayCrossesTheRedactionBoundary(t *testing.T) {
	recs := []map[string]any{
		{"conn_id": 1, "kind": "request", "source_workload": "a", "destination_workload": "b", "destination_port": 80,
			"text": "POST /x HTTP/1.1\r\nCookie: sid=CREDSECRET\r\nContent-Length: 11\r\n\r\nBODYSECRET!"},
	}
	raw, _ := json.Marshal(recs)
	path := filepath.Join(t.TempDir(), "l7.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewFixtureL7Source(path)
	if err != nil {
		t.Fatal(err)
	}
	src.applyBoundary(RedactMetadata, headerValuePolicy{})
	p := src.events[0].Data.Payload
	if bytes.Contains(p, []byte("CREDSECRET")) || bytes.Contains(p, []byte("BODYSECRET")) {
		t.Fatalf("fixture payload crossed the boundary unredacted: %q", p)
	}
	if src.events[0].Data.Size != len(recs[0]["text"].(string)) {
		t.Fatalf("true size lost: %d", src.events[0].Data.Size)
	}
}

// D-43 S7: under length no parsed call leaves the agent.
func TestAgentEmitsNoCallUnderLength(t *testing.T) {
	em := &captureEmitter{}
	cfg := &Config{TenantID: "t1", Host: "n", FlushInterval: time.Hour, L7CaptureRedaction: RedactLengthOnly}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &sliceSource{}, NopEnricher{}, em)
	t0 := time.Unix(0, 0)
	a.l7source = &sliceL7Source{events: []L7Event{
		{ConnID: 1, TenantID: "t1", Data: l7.DataEvent{Kind: l7.Request, Time: t0, Payload: []byte("GET /a HTTP/1.1\r\nContent-Length: 0\r\n\r\n")}},
		{ConnID: 1, Data: l7.DataEvent{Kind: l7.Response, Time: t0, Payload: []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")}},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(em.l7) != 0 {
		t.Fatalf("length mode emitted %d calls", len(em.l7))
	}
}
