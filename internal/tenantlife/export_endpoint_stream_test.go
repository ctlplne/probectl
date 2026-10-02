// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
)

// fileFromBundle untars a bundle and returns one named file's raw bytes.
func fileFromBundle(t *testing.T, buf *bytes.Buffer, name string) []byte {
	t.Helper()
	gz, err := gzip.NewReader(buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name != name {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) != hdr.Size {
			t.Fatalf("%s: tar header size %d != %d bytes written (streamed header must match the staged plane)", name, hdr.Size, len(data))
		}
		return data
	}
	t.Fatalf("%s not in bundle", name)
	return nil
}

// TestEndpointPlaneStreamsAndRedactsEquivalently proves the temp-file-staged
// endpoint plane (GAP-05 streaming) is byte-identical to the previous
// whole-buffer behavior: plain output carries PII in clear, and redacted output
// equals govern.RedactJSONL applied to the plain plane — exactly what the old
// buffer-then-RedactJSONL path produced — with the tar header size matching the
// streamed bytes. It exercises streamPlaneToTar and redactingLineWriter end to
// end, keeping tenant scoping (only tnA's rows appear).
func TestEndpointPlaneStreamsAndRedactsEquivalently(t *testing.T) {
	defer govern.Reset()

	seed := func() endpointstore.Store {
		s := endpointstore.NewMemory()
		if err := s.Insert(context.Background(), []endpointstore.Event{
			{TenantID: "tnA", AgentID: "laptop-a", Type: "endpoint.wifi", Target: "A-SSID",
				Attributes: map[string]string{"gateway": "198.51.100.7"}, ObservedAt: t0},
			{TenantID: "tnB", AgentID: "decoy-b", Type: "endpoint.wifi", Target: "SECRET-B",
				Attributes: map[string]string{"gateway": "203.0.113.9"}, ObservedAt: t0},
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}

	newEngine := func() *Engine {
		return New(nil, nil, nil, nil, (&capturedAudit{}).sink, "", testLog()).
			WithClock(func() time.Time { return t0 }).
			WithEndpointEvents(seed())
	}

	var plain bytes.Buffer
	manPlain, err := newEngine().Export(context.Background(), "tnA", &plain)
	if err != nil {
		t.Fatal(err)
	}
	plainEP := fileFromBundle(t, &plain, "endpoint_events.jsonl")

	if manPlain.EndpointEvents != 1 {
		t.Fatalf("manifest endpoint count = %d, want 1 (tenant-scoped)", manPlain.EndpointEvents)
	}
	if !bytes.Contains(plainEP, []byte("198.51.100.7")) {
		t.Fatalf("plain endpoint export must keep the gateway IP in clear: %s", plainEP)
	}
	if bytes.Contains(plainEP, []byte("203.0.113.9")) || bytes.Contains(plainEP, []byte("SECRET-B")) {
		t.Fatalf("tenant B's endpoint event leaked into tnA's export: %s", plainEP)
	}

	var red bytes.Buffer
	manRed, err := newEngine().ExportRedacted(context.Background(), "tnA", &red, true)
	if err != nil {
		t.Fatal(err)
	}
	if !manRed.Redacted || manRed.EndpointEvents != 1 {
		t.Fatalf("redacted manifest unexpected: %+v", manRed)
	}
	redEP := fileFromBundle(t, &red, "endpoint_events.jsonl")

	// The streamed, line-by-line redaction must equal the old whole-buffer path:
	// govern.RedactJSONL under the same effective policy (DefaultPIIPolicy when
	// no governance source forces a class).
	want := govern.RedactJSONL(govern.DefaultPIIPolicy(), plainEP)
	if !bytes.Equal(redEP, want) {
		t.Fatalf("streamed redaction diverged from whole-buffer RedactJSONL\n got: %s\nwant: %s", redEP, want)
	}
	if bytes.Contains(redEP, []byte("198.51.100.7")) {
		t.Fatalf("redacted endpoint export must mask the gateway IP: %s", redEP)
	}
}
