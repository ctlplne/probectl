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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/browser"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

var t0 = time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestFullTenantExportTableClassificationExcludesRetainedIREvidence(t *testing.T) {
	got := ordinaryPortabilityExportTables([]string{
		"agents",
		"ir_attribution_records",
		"tests",
		"ir_attribution_heads",
	})
	if joined := strings.Join(got, ","); joined != "agents,tests" {
		t.Fatalf("ordinary portability tables = %q, want %q", joined, "agents,tests")
	}
	if ordinaryPortabilityIRPolicyNote !=
		"Ordinary portability exports never include encrypted incident-response attribution. Investigation access, where applicable, is only through the audited IR-investigator path. This policy statement does not indicate whether any records exist." {
		t.Fatal("ordinary portability IR policy note changed")
	}
}

type capturedAudit struct {
	events []string
	data   []map[string]any
}

func (c *capturedAudit) sink(_ context.Context, _, action, _ string, data map[string]any) error {
	c.events = append(c.events, action)
	c.data = append(c.data, data)
	return nil
}

type artifactDriver struct{}

func (artifactDriver) Name() string { return "artifact" }

func (artifactDriver) Run(context.Context, browser.Script) (browser.RunOutput, error) {
	return browser.RunOutput{
		Result: browser.Result{
			Script:    "login",
			Success:   false,
			Error:     "assertion failed",
			StartedAt: t0,
			TotalMs:   25,
		},
		Screenshot:     []byte("PNGBYTES"),
		ScreenshotType: "image/png",
	}, nil
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

type objectVerificationErrorStore struct {
	objectstore.Store
	prefix string
	err    error
}

func (s objectVerificationErrorStore) List(ctx context.Context, prefix string) ([]string, error) {
	if prefix == s.prefix {
		return nil, s.err
	}
	return s.Store.List(ctx, prefix)
}

func TestEraseObjectVerificationErrorFailsClosedAndPreservesOtherTenant(t *testing.T) {
	ctx := context.Background()
	objects := objectstore.NewMemory()
	for key, body := range map[string]string{
		objectstore.TenantKey("tnA", "browser", "delete.png"): "tenant-a-pooled",
		"silo/tnA/browser/delete.png":                         "tenant-a-silo",
		objectstore.TenantKey("tnB", "browser", "keep.png"):   "tenant-b-pooled",
		"silo/tnB/browser/keep.png":                           "tenant-b-silo",
	} {
		if err := objects.Put(ctx, key, "image/png", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	verifyErr := errors.New("object inventory unavailable")
	failing := objectVerificationErrorStore{
		Store:  objects,
		prefix: objectstore.TenantKey("tnA") + "/",
		err:    verifyErr,
	}
	audit := &capturedAudit{}
	e := New(nil, nil, failing, nil, audit.sink, "", testLog()).
		WithClock(func() time.Time { return t0 })

	att, err := e.Erase(ctx, "tnA", "acme", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if att.Complete {
		t.Fatalf("unverifiable object erasure reported complete: %+v", att.Stores)
	}
	var objectResult *StoreResult
	objectResults := 0
	for i := range att.Stores {
		if att.Stores[i].Store == "objects" {
			objectResults++
			objectResult = &att.Stores[i]
		}
	}
	if objectResults != 1 || objectResult == nil {
		t.Fatalf("object verification failure missing from attestation: %+v", att.Stores)
	}
	if objectResult.Deleted != -1 || objectResult.VerifiedZero ||
		!strings.Contains(objectResult.Notes, verifyErr.Error()) {
		t.Fatalf("object verification failure was misreported: %+v", *objectResult)
	}
	if keys, listErr := objects.List(ctx, objectstore.TenantKey("tnB")+"/"); listErr != nil || len(keys) != 1 {
		t.Fatalf("tenant B pooled objects changed: keys=%v err=%v", keys, listErr)
	}
	if keys, listErr := objects.List(ctx, "silo/tnB/"); listErr != nil || len(keys) != 1 {
		t.Fatalf("tenant B silo objects changed: keys=%v err=%v", keys, listErr)
	}
	if att.ReportSHA256 == "" || att.hash() != att.ReportSHA256 {
		t.Fatalf("incomplete attestation hash is not verifiable: %+v", att)
	}
	if len(audit.events) != 1 || audit.events[0] != "lifecycle.erase" ||
		audit.data[0]["complete"] != false {
		t.Fatalf("incomplete lifecycle receipt = events %v data %+v", audit.events, audit.data)
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
	endpointEvents := endpointstore.NewMemory()
	if err := endpointEvents.Insert(context.Background(), []endpointstore.Event{
		{TenantID: "tnA", AgentID: "laptop-a", Type: "endpoint.wifi", Target: "A-SSID", ObservedAt: t0},
		{TenantID: "tnB", AgentID: "decoy-b", Type: "endpoint.wifi", Target: "SECRET-B", ObservedAt: t0},
	}); err != nil {
		t.Fatal(err)
	}
	audit := &capturedAudit{}
	e := New(nil, flows, objects, mem, audit.sink, "", testLog()).
		WithClock(func() time.Time { return t0 }).
		WithEndpointEvents(endpointEvents)

	var buf bytes.Buffer
	man, err := e.Export(context.Background(), "tnA", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if man.Flows != 2 || man.EndpointEvents != 1 || len(man.Objects) != 2 {
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
	endpointLines := strings.Split(strings.TrimSpace(string(files["endpoint_events.jsonl"])), "\n")
	if len(endpointLines) != 1 || strings.Contains(endpointLines[0], "SECRET-B") {
		t.Fatalf("endpoint event export crossed tenant boundary: %q", endpointLines)
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

func TestEndpointDurableRetentionLifecycle(t *testing.T) {
	ctx := context.Background()
	events := endpointstore.NewMemory()
	if err := events.Insert(ctx, []endpointstore.Event{
		{TenantID: "tnA", AgentID: "old", Type: "endpoint.wifi", ObservedAt: t0.Add(-48 * time.Hour)},
		{TenantID: "tnA", AgentID: "new", Type: "endpoint.wifi", ObservedAt: t0.Add(-1 * time.Hour)},
		{TenantID: "tnB", AgentID: "neighbor", Type: "endpoint.wifi", ObservedAt: t0.Add(-48 * time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	audit := &capturedAudit{}
	e := New(nil, nil, nil, nil, audit.sink, "", testLog()).
		WithClock(func() time.Time { return t0 }).
		WithEndpointEvents(events).
		WithDerivedIdentityRetentionDays(1)
	if err := e.pruneDerivedIdentityCaches(ctx, retentionSweepPolicy{tenant: "tnA"}); err != nil {
		t.Fatal(err)
	}
	if rows, _ := events.Latest(ctx, "tnA"); len(rows) != 1 || rows[0].AgentID != "new" {
		t.Fatalf("tenant endpoint retention rows = %+v, want only new", rows)
	}
	if rows, _ := events.Latest(ctx, "tnB"); len(rows) != 1 {
		t.Fatalf("neighbor endpoint retention rows damaged: %+v", rows)
	}
	if len(audit.events) != 2 ||
		audit.data[0]["store"] != "endpoint_events" ||
		audit.data[0]["status"] != "intent" ||
		audit.data[1]["status"] != "enforced" ||
		audit.data[1]["deleted"] != int64(1) {
		t.Fatalf("endpoint retention receipt = events %v data %+v", audit.events, audit.data)
	}
}

func TestBrowserArtifactsAreLifecycleVisibleAndErasable(t *testing.T) {
	ctx := context.Background()
	objects := objectstore.NewMemory()
	fleet := browser.NewFleet(browser.Config{MaxConcurrency: 1}, func() browser.Driver {
		return artifactDriver{}
	}, objects, testLog())
	defer fleet.Close()

	res, err := fleet.Run(ctx, "tnA", browser.Script{
		Name:     "login",
		StartURL: "https://app.example/login",
		Steps:    []browser.Step{{Name: "shot", Action: browser.Screenshot}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Screenshot == nil || !strings.HasPrefix(res.Screenshot.Key, "tenant/tnA/browser/") {
		t.Fatalf("browser artifact must be tenant-prefixed: %+v", res.Screenshot)
	}
	if err := objects.Put(ctx, objectstore.TenantKey("tnB", "browser", "keep.png"), "image/png", []byte("neighbor")); err != nil {
		t.Fatal(err)
	}

	audit := &capturedAudit{}
	e := New(nil, nil, objects, nil, audit.sink, "", testLog()).
		WithClock(func() time.Time { return t0 })
	var buf bytes.Buffer
	man, err := e.Export(ctx, "tnA", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(man.Objects) != 1 || man.Objects[0].Key != res.Screenshot.Key {
		t.Fatalf("tenant export must inventory the browser artifact only: %+v", man.Objects)
	}

	att, err := e.Erase(ctx, "tnA", "acme", "op")
	if err != nil {
		t.Fatal(err)
	}
	if !att.Complete {
		t.Fatalf("attestation should be complete: %+v", att.Stores)
	}
	if keys, _ := objects.List(ctx, "tenant/tnA/"); len(keys) != 0 {
		t.Fatalf("tenant browser artifact remained after erase: %v", keys)
	}
	if keys, _ := objects.List(ctx, "tenant/tnB/"); len(keys) != 1 {
		t.Fatalf("neighbor tenant artifact was damaged: %v", keys)
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
		tenant: "tnA",
		days:   map[string]int{"flows": 14},
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
	if len(audit.events) != 4 {
		t.Fatalf("derived retention receipts missing: %v", audit.events)
	}
	stores := map[string]int{}
	for _, data := range audit.data {
		if data["status"] == "intent" {
			continue
		}
		stores[data["store"].(string)] = int(data["deleted"].(int64))
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

func TestRetentionSweepPerPlanePoliciesPruneAndReceipt(t *testing.T) {
	ctx := context.Background()
	otel := otelstore.NewMemory()
	if err := otel.WriteSpans(ctx, []otelstore.Span{
		{TenantID: "tnA", TraceID: "old", SpanID: "s1", Service: "api", Start: t0.Add(-48 * time.Hour)},
		{TenantID: "tnA", TraceID: "new", SpanID: "s2", Service: "api", Start: t0.Add(-1 * time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := otel.WriteLogs(ctx, []otelstore.LogRecord{
		{TenantID: "tnA", TS: t0.Add(-48 * time.Hour), Service: "api", Body: "old"},
		{TenantID: "tnA", TS: t0.Add(-1 * time.Hour), Service: "api", Body: "new"},
	}); err != nil {
		t.Fatal(err)
	}
	ebpf := ebpfstore.NewMemory()
	if err := ebpf.Insert(ctx, []ebpfstore.Edge{
		{TenantID: "tnA", AgentID: "a", SrcWorkload: "old", DstWorkload: "api", WindowStart: t0.Add(-48 * time.Hour)},
		{TenantID: "tnA", AgentID: "a", SrcWorkload: "new", DstWorkload: "api", WindowStart: t0.Add(-1 * time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	audit := &capturedAudit{}
	e := New(nil, nil, nil, nil, audit.sink, "", testLog()).
		WithClock(func() time.Time { return t0 }).
		WithOtel(otel).
		WithEBPF(ebpf)
	p := retentionSweepPolicy{tenant: "tnA", days: map[string]int{
		"otel":    1,
		"ebpf":    1,
		"objects": 7,
	}}

	if err := e.sweepOtelRetention(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := e.sweepEBPFRetention(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := e.receiptDelegatedRetention(ctx, p, "objects", "object_store_lifecycle"); err != nil {
		t.Fatal(err)
	}

	if spans, logs := otel.Len("tnA"); spans != 1 || logs != 1 {
		t.Fatalf("otel retention counts = spans %d logs %d, want 1/1", spans, logs)
	}
	edges, err := ebpf.TopEdges(ctx, "tnA", ebpfstore.EdgeQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || edges[0].SrcWorkload != "new" {
		t.Fatalf("ebpf retention edges = %+v, want only new", edges)
	}
	byStore := map[string]map[string]any{}
	for _, data := range audit.data {
		byStore[data["store"].(string)] = data
	}
	for store, wantDeleted := range map[string]int64{"otel": 2, "ebpf": 1} {
		if byStore[store]["status"] != "enforced" || byStore[store]["deleted"] != wantDeleted {
			t.Fatalf("%s receipt = %+v", store, byStore[store])
		}
	}
	if byStore["objects"]["status"] != "delegated" ||
		byStore["objects"]["retention_days"] == nil {
		t.Fatalf("object delegated receipt = %+v", byStore["objects"])
	}
	if _, found := byStore["audit"]; found {
		t.Fatalf("lifecycle sweep emitted misleading delegated audit receipt: %+v", byStore["audit"])
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
