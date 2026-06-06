package tenantlife

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

// TestRedactedExport is the named redaction/masking test (S-EE3): a requested
// redacted export masks PII-class values (flow src/dst IPs) while non-sensitive
// fields survive — and the plain export keeps everything in clear.
func TestRedactedExport(t *testing.T) {
	flows := flowstore.NewMemory()
	if err := flows.Insert(context.Background(), []flowstore.Row{
		{TenantID: "tnA", TS: t0, SrcAddr: "198.51.100.7", DstAddr: "203.0.113.9", Bytes: 64, Protocol: "ipfix"},
	}); err != nil {
		t.Fatal(err)
	}
	audit := &capturedAudit{}
	e := New(nil, flows, nil, nil, audit.sink, "", testLog()).
		WithClock(func() time.Time { return t0 })

	// Plain export: IPs are in clear.
	var plain bytes.Buffer
	if _, err := e.Export(context.Background(), "tnA", &plain); err != nil {
		t.Fatal(err)
	}
	plainFlows := flowsFromBundle(t, &plain)
	if plainFlows["src_addr"] != "198.51.100.7" || plainFlows["dst_addr"] != "203.0.113.9" {
		t.Fatalf("plain export must keep IPs in clear: %+v", plainFlows)
	}

	// Redacted export: IPs masked to their network; bytes/protocol survive.
	var red bytes.Buffer
	man, err := e.ExportRedacted(context.Background(), "tnA", &red, true)
	if err != nil {
		t.Fatal(err)
	}
	if !man.Redacted {
		t.Fatal("manifest must record Redacted=true")
	}
	redFlows := flowsFromBundle(t, &red)
	if redFlows["src_addr"] != "198.51.100.0/24" || redFlows["dst_addr"] != "203.0.113.0/24" {
		t.Fatalf("redacted export must mask IPs to /24: %+v", redFlows)
	}
	if redFlows["bytes"] != float64(64) || redFlows["protocol"] != "ipfix" {
		t.Fatalf("non-PII fields must survive redaction: %+v", redFlows)
	}
}

// TestRedactedExportHonorsPolicy: when a governance source forces redaction
// (RedactExport=true), even a non-redacted request is masked.
func TestRedactedExportHonorsPolicy(t *testing.T) {
	defer govern.Reset()
	govern.SetSource(forceRedact{})

	flows := flowstore.NewMemory()
	_ = flows.Insert(context.Background(), []flowstore.Row{
		{TenantID: "tnA", TS: t0, SrcAddr: "10.0.0.5", Bytes: 1},
	})
	e := New(nil, flows, nil, nil, (&capturedAudit{}).sink, "", testLog()).
		WithClock(func() time.Time { return t0 })

	var buf bytes.Buffer
	man, err := e.Export(context.Background(), "tnA", &buf) // redact=false, but policy forces it
	if err != nil {
		t.Fatal(err)
	}
	if !man.Redacted {
		t.Fatal("a force-redact policy must redact even an unrequested export")
	}
	if got := flowsFromBundle(t, &buf)["src_addr"]; got != "10.0.0.0/24" {
		t.Fatalf("policy-forced redaction: %q", got)
	}
}

type forceRedact struct{}

func (forceRedact) PolicyFor(context.Context, string) (govern.Policy, bool, error) {
	return govern.Policy{RedactExport: true, RedactFrom: govern.ClassPII}, true, nil
}

// flowsFromBundle untars a bundle and returns the first flows.jsonl record.
func flowsFromBundle(t *testing.T, buf *bytes.Buffer) map[string]any {
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
		if hdr.Name != "flows.jsonl" {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		line := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)[0]
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("flows.jsonl line not JSON: %q (%v)", line, err)
		}
		return row
	}
	t.Fatal("flows.jsonl not in bundle")
	return nil
}
