// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tenantlife

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

var t0 = time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type capturedAudit struct {
	events []string
	data   []map[string]any
}

func (c *capturedAudit) sink(_ context.Context, _, action, _ string, data map[string]any) error {
	c.events = append(c.events, action)
	c.data = append(c.data, data)
	return nil
}

func seedStores(t *testing.T) (flowstore.Store, *objectstore.MemStore, *tsdb.Memory) {
	t.Helper()
	ctx := context.Background()
	flows := flowstore.NewMemory()
	if err := flows.Insert(ctx, []flowstore.Row{
		{TenantID: "tnA", TS: t0.Add(-48 * time.Hour), Bytes: 1},
		{TenantID: "tnA", TS: t0.Add(-1 * time.Hour), Bytes: 2},
		{TenantID: "tnB", TS: t0.Add(-1 * time.Hour), Bytes: 3},
	}); err != nil {
		t.Fatal(err)
	}
	objects := objectstore.NewMemory()
	for key, body := range map[string]string{
		objectstore.TenantKey("tnA", "browser", "shot1.png"): "a1",
		"silo/tnA/browser/shot2.png":                         "a2",
		objectstore.TenantKey("tnB", "browser", "keep.png"):  "b1",
	} {
		if err := objects.Put(ctx, key, "image/png", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	mem := tsdb.NewMemory()
	_ = mem.Write(ctx, []tsdb.Series{
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnA"}, Value: 1},
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnA"}, Value: 2},
		{Metric: "probe_rtt", Labels: map[string]string{"tenant_id": "tnB"}, Value: 3},
	})
	return flows, objects, mem
}

// TestEraseGoneFromEveryStore is the named deletion test (store-level): after
// Erase, tenant A's data reads ZERO in flows, objects, and the TSDB — while
// tenant B's data is untouched — and the attestation is audit-grade
// (per-store verification + provider-stream append + a stable report hash).
func TestEraseGoneFromEveryStore(t *testing.T) {
	flows, objects, mem := seedStores(t)
	audit := &capturedAudit{}
	e := New(nil, flows, objects, mem, audit.sink, "backups expire after 30 days", testLog()).
		WithClock(func() time.Time { return t0 })

	att, err := e.Erase(context.Background(), "tnA", "acme", "admin@msp.example")
	if err != nil {
		t.Fatal(err)
	}
	if !att.Complete {
		t.Fatalf("attestation must be complete: %+v", att)
	}

	// Gone from every store…
	ctx := context.Background()
	if remaining, _ := flows.DeleteTenant(ctx, "tnA"); remaining != 0 {
		t.Fatalf("flows remaining: %d", remaining)
	}
	if keys, _ := objects.List(ctx, "tenant/tnA/"); len(keys) != 0 {
		t.Fatalf("objects remaining: %v", keys)
	}
	if keys, _ := objects.List(ctx, "silo/tnA/"); len(keys) != 0 {
		t.Fatalf("silo objects remaining: %v", keys)
	}
	if n, _ := mem.DeleteTenant(ctx, "tnA"); n != 0 {
		t.Fatalf("tsdb series remaining: %d", n)
	}
	// …while tenant B is untouched.
	if keys, _ := objects.List(ctx, "tenant/tnB/"); len(keys) != 1 {
		t.Fatalf("tenant B objects must be untouched: %v", keys)
	}
	if n, _ := mem.DeleteTenant(ctx, "tnB"); n != 1 {
		t.Fatalf("tenant B series must be untouched: %d", n)
	}

	// The attestation: per-store verification, the backup-TTL statement, the
	// provider-stream append, and a verifiable report hash.
	byStore := map[string]StoreResult{}
	for _, s := range att.Stores {
		byStore[s.Store] = s
	}
	for _, store := range []string{"flows", "objects", "tsdb"} {
		if !byStore[store].VerifiedZero {
			t.Fatalf("%s must verify zero: %+v", store, byStore[store])
		}
	}
	if byStore["objects"].Deleted != 2 || byStore["tsdb"].Deleted != 2 {
		t.Fatalf("deletion counts: %+v", byStore)
	}
	if att.BackupPolicy != "backups expire after 30 days" {
		t.Fatalf("backup policy must ride the attestation: %q", att.BackupPolicy)
	}
	if len(audit.events) != 1 || audit.events[0] != "lifecycle.erase" {
		t.Fatalf("erasure must append to the provider audit stream: %v", audit.events)
	}
	if audit.data[0]["report_sha256"] != att.ReportSHA256 {
		t.Fatal("the audited hash must match the report")
	}
	if att.hash() != att.ReportSHA256 {
		t.Fatal("the report hash must be recomputable (tamper evidence)")
	}
	tampered := att
	tampered.TenantSlug = "evil"
	if tampered.hash() == att.ReportSHA256 {
		t.Fatal("a tampered report must not hash-match")
	}
}

// TestEraseHonestyOnPrometheusTSDB: a TSDB writer that cannot delete in place
// (prometheus mode) marks the attestation INCOMPLETE with the documented
// manual step — never a silent pass.
func TestEraseHonestyOnPrometheusTSDB(t *testing.T) {
	flows, objects, _ := seedStores(t)
	audit := &capturedAudit{}
	e := New(nil, flows, objects, promLike{}, audit.sink, "", testLog())

	att, err := e.Erase(context.Background(), "tnA", "acme", "op")
	if err != nil {
		t.Fatal(err)
	}
	if att.Complete {
		t.Fatal("a manual-step store must mark the attestation incomplete")
	}
	found := false
	for _, s := range att.Stores {
		if s.Store == "tsdb" && strings.Contains(s.Notes, "MANUAL STEP REQUIRED") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tsdb manual step must be on the record: %+v", att.Stores)
	}
}

type promLike struct{}

func (promLike) Write(context.Context, []tsdb.Series) error { return nil }
func (promLike) Close() error                               { return nil }

// TestExportRoundTrip is the named export test (store-level): seed → export →
// parse the tar.gz → the bundle carries exactly the tenant's flows + the
// object inventory + a manifest whose counts match, and nothing of tenant B.
func TestExportRoundTrip(t *testing.T) {
	flows, objects, mem := seedStores(t)
	audit := &capturedAudit{}
	e := New(nil, flows, objects, mem, audit.sink, "", testLog()).
		WithClock(func() time.Time { return t0 })

	var buf bytes.Buffer
	man, err := e.Export(context.Background(), "tnA", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if man.Flows != 2 || len(man.Objects) != 2 {
		t.Fatalf("manifest counts: %+v", man)
	}

	// Parse the bundle.
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		files[hdr.Name] = b
	}
	if _, ok := files["manifest.json"]; !ok {
		t.Fatalf("bundle files: %v", keysOf(files))
	}
	var parsed Manifest
	if err := json.Unmarshal(files["manifest.json"], &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.FormatVersion != 1 || parsed.TenantID != "tnA" || parsed.Flows != 2 {
		t.Fatalf("parsed manifest: %+v", parsed)
	}
	flowLines := strings.Split(strings.TrimSpace(string(files["flows.jsonl"])), "\n")
	if len(flowLines) != 2 {
		t.Fatalf("flow lines: %d", len(flowLines))
	}
	for _, line := range flowLines {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row["tenant_id"] != "tnA" {
			t.Fatalf("a foreign tenant's flow leaked into the export: %v", row)
		}
	}
	// The object inventory names only tenant A's keys.
	for _, o := range parsed.Objects {
		if strings.Contains(o.Key, "tnB") {
			t.Fatalf("tenant B's object leaked into the inventory: %v", o)
		}
	}
	if len(audit.events) != 1 || audit.events[0] != "lifecycle.export" {
		t.Fatalf("export must be audited: %v", audit.events)
	}
}

// TestRetentionSweepStoreLevel: the flow-store retention primitive removes
// only the right tenant's rows past the cutoff.
func TestRetentionSweepStoreLevel(t *testing.T) {
	flows, _, _ := seedStores(t)
	ctx := context.Background()
	// Cut tenant A at 24h: the 48h-old row goes, the 1h-old stays; B untouched.
	if err := flows.DeleteTenantBefore(ctx, "tnA", t0.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n, err := flows.ExportTenant(ctx, "tnA", &buf)
	if err != nil || n != 1 {
		t.Fatalf("tenant A after retention: %d %v", n, err)
	}
	buf.Reset()
	n, err = flows.ExportTenant(ctx, "tnB", &buf)
	if err != nil || n != 1 {
		t.Fatalf("tenant B must be untouched: %d %v", n, err)
	}
}

type retentionPruner struct {
	deleted int
	calls   []retentionPruneCall
}

type retentionPruneCall struct {
	tenant string
	cutoff time.Time
}

func (p *retentionPruner) PruneTenantBefore(tenant string, cutoff time.Time) int {
	p.calls = append(p.calls, retentionPruneCall{tenant: tenant, cutoff: cutoff})
	return p.deleted
}

type topologyRetentionPruner struct {
	retentionPruner
}

func (p *topologyRetentionPruner) DeleteTenant(string) int { return 0 }

func TestRetentionSweepPrunesDerivedIdentityCachesAndReceipts(t *testing.T) {
	topo := &topologyRetentionPruner{retentionPruner: retentionPruner{deleted: 2}}
	endpoints := &retentionPruner{deleted: 1}
	audit := &capturedAudit{}
	e := New(nil, nil, nil, nil, audit.sink, "", testLog()).
		WithClock(func() time.Time { return t0 }).
		WithTopology(topo).
		WithEndpointRetention(endpoints).
		WithDerivedIdentityRetentionDays(90)

	err := e.pruneDerivedIdentityCaches(context.Background(), retentionSweepPolicy{
		tenant:      "tnA",
		flowDays:    14,
		hasFlowDays: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantCutoff := t0.Add(-14 * 24 * time.Hour)
	if len(topo.calls) != 1 || topo.calls[0].tenant != "tnA" || !topo.calls[0].cutoff.Equal(wantCutoff) {
		t.Fatalf("topology prune call = %+v, want tenant tnA cutoff %s", topo.calls, wantCutoff)
	}
	if len(endpoints.calls) != 1 || endpoints.calls[0].tenant != "tnA" || !endpoints.calls[0].cutoff.Equal(wantCutoff) {
		t.Fatalf("endpoint prune call = %+v, want tenant tnA cutoff %s", endpoints.calls, wantCutoff)
	}
	if len(audit.events) != 2 || audit.events[0] != "lifecycle.retention_sweep" || audit.events[1] != "lifecycle.retention_sweep" {
		t.Fatalf("derived retention receipts missing: %v", audit.events)
	}
	stores := map[string]int{}
	for _, data := range audit.data {
		stores[data["store"].(string)] = data["deleted"].(int)
		if data["source"] != "derived_identity_cache" || data["retention_days"] != 14 {
			t.Fatalf("receipt data = %+v", data)
		}
		if data["cutoff"] != wantCutoff.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("receipt cutoff = %v, want %s", data["cutoff"], wantCutoff.UTC().Format(time.RFC3339Nano))
		}
	}
	if stores["topology"] != 2 || stores["endpoint"] != 1 {
		t.Fatalf("receipt stores = %+v", stores)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
