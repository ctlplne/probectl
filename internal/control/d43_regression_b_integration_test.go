// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/ebpf"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/support"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat"
	"github.com/ctlplne/probectl/internal/topology"
)

// The bytes D-43 regression test (b) hunts for. Each one is a value the L7
// fixture carries that metadata mode must never let out of the agent, nor the
// control plane let into any store: a request body, a credential and two
// identity header values, a cookie, query-string values, and the raw
// identifier path segment. None is key-shaped (secret-scan safe).
var d43Needles = []string{
	"W56HZV-23-C-0123",              // the raw contract-number path segment
	"QUERYSSN987",                   // query-string values
	"QUERYSESSION",                  //
	"credvalue-not-a-real-token",    // Authorization header value
	"pat.person@contractor.example", // identity header value
	"records.internal",              // Host header value
	"BODYCUI-CONTROLLED-7731",       // request body
	"COOKIESECRETVALUE",             // Set-Cookie value
}

const d43Request = "POST /contracts/W56HZV-23-C-0123/drawings?ssn=QUERYSSN987&session=QUERYSESSION HTTP/1.1\r\n" +
	"Host: records.internal\r\n" +
	"Authorization: Bearer credvalue-not-a-real-token\r\n" +
	"X-User-Email: pat.person@contractor.example\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 38\r\n\r\n" +
	`{"diagnosis":"BODYCUI-CONTROLLED-7731"`

// recordingBus keeps every published record (the bus is where Kafka and NATS
// JetStream would retain them) and delivers nothing by itself.
type recordingBus struct {
	mu   sync.Mutex
	msgs []bus.Message
}

func (r *recordingBus) Publish(_ context.Context, topic string, key, value []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, bus.Message{Topic: topic, Key: append([]byte(nil), key...), Value: append([]byte(nil), value...)})
	return nil
}
func (r *recordingBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (r *recordingBus) Close() error                                                 { return nil }

func (r *recordingBus) snapshot() []bus.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bus.Message(nil), r.msgs...)
}

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func d43WriteJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// d43Stack is the real control plane under test: the agent gRPC listener with
// the database-backed L7 policy, and a test CA that issues agent SVIDs.
type d43Stack struct {
	addr, caFile, dir string
	ca                *crypto.CA
}

func startD43Stack(t *testing.T, db *store.DB, ctlLog *slog.Logger) d43Stack {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("d43-regression-b", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caFile := write("ca.pem", ca.CertPEM())
	srv, err := agenttransport.New(write("srv.pem", sc), write("srv.key", sk), caFile, db.Pool(), bus.NewMemory(), nil, ctlLog)
	if err != nil {
		t.Fatal(err)
	}
	srv.WithL7Policy(agenttransport.NewL7Policy(db.Pool(), false))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.ServeListener(ctx, ln); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return d43Stack{addr: ln.Addr().String(), caFile: caFile, dir: dir, ca: ca}
}

// runD43Agent runs one real eBPF agent (fixture flows + the L7 fixture through
// the agent's capture boundary) against the control plane's policy channel,
// publishing onto rb.
func runD43Agent(t *testing.T, st d43Stack, tenant, agentID, redaction, flowsPath, l7Path string, rb bus.Bus, agentLog *slog.Logger) {
	t.Helper()
	cert, key, err := st.ca.IssueClientCert(agentID, crypto.EBPFSPIFFEID(tenant, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(st.dir, agentID+".pem")
	keyFile := filepath.Join(st.dir, agentID+".key")
	if err := os.WriteFile(certFile, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := ebpf.Default()
	cfg.TenantID, cfg.AgentID, cfg.Host = tenant, agentID, "node-"+agentID[:8]
	cfg.FixturePath, cfg.L7FixturePath = flowsPath, l7Path
	cfg.FlushInterval = time.Hour // one final flush when the fixtures are exhausted
	cfg.L7CaptureEnabled, cfg.L7CaptureConsentTenant = true, tenant
	cfg.L7CaptureScope = []string{"exe:/opt/records/bin/records-api"}
	cfg.L7CaptureRedaction = redaction
	cfg.ControlPlane = ebpf.ControlPlaneConfig{GRPCAddr: st.addr, ServerName: "localhost", CertFile: certFile, KeyFile: keyFile, CAFile: st.caFile}
	agent, err := ebpf.New(cfg, rb, agentLog.With("agent", agentID))
	if err != nil {
		t.Fatalf("agent %s: %v", agentID, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := agent.Run(ctx); err != nil {
		t.Fatalf("agent %s run: %v", agentID, err)
	}
}

// legacyRecord is what an outdated or hostile producer holding the tenant's bus
// credential could publish: the full call, query string and identifier path
// intact, and header/body bytes riding fields the schema does not know.
func legacyRecord(t *testing.T, tenant, agentID string) []byte {
	t.Helper()
	call := &ebpfv1.L7Call{
		TenantId: tenant, AgentId: agentID, Source: "portal", Destination: "records", DestinationPort: 8443,
		Protocol: "http1", Method: "POST", Status: "201",
		Resource: "/contracts/W56HZV-23-C-0123/drawings?ssn=QUERYSSN987&session=QUERYSESSION",
	}
	callRaw, err := proto.Marshal(call)
	if err != nil {
		t.Fatal(err)
	}
	callRaw = protowire.AppendBytes(protowire.AppendTag(callRaw, 90, protowire.BytesType),
		[]byte("Authorization: Bearer credvalue-not-a-real-token\r\nX-User-Email: pat.person@contractor.example\r\nHost: records.internal"))
	callRaw = protowire.AppendBytes(protowire.AppendTag(callRaw, 91, protowire.BytesType), []byte(`{"diagnosis":"BODYCUI-CONTROLLED-7731"} COOKIESECRETVALUE`))
	raw, err := proto.Marshal(&ebpfv1.FlowBatch{Flows: []*ebpfv1.Flow{{
		TenantId: tenant, AgentId: agentID, Host: "legacy", SourceAddress: "10.9.0.1", DestinationAddress: "10.9.0.2",
		DestinationPort: 8443, NetworkTransport: "tcp", Bytes: 10, Packets: 1, ObservedAtUnixNano: time.Now().UnixNano(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return protowire.AppendBytes(protowire.AppendTag(raw, 3, protowire.BytesType), callRaw)
}

func findNeedles(hay []byte) []string {
	var found []string
	for _, n := range d43Needles {
		if bytes.Contains(hay, []byte(n)) {
			found = append(found, n)
		}
	}
	return found
}

// D-43 regression test (b), widened by refinement 3. One tenant on the metadata
// floor (no policy row: the default). Three probectl eBPF agents replay the
// same L7 fixture through the real agent pipeline and fetch the floor over the
// real mTLS agent channel: one in metadata mode, and two deliberately
// misconfigured with headers and full set locally. A fourth producer — an
// outdated or hostile one holding the tenant's bus credential — publishes the
// raw call straight to the bus. Every record then goes through the control
// plane's ingest door into the real consumers and stores, and a support bundle
// is generated through the API. The byte search covers the bus records the
// probectl agents published, both agents' and the control plane's logs, the
// ingest output every consumer reads, every persisted row, and the decompressed
// support bundle.
func TestD43RegressionB_NoCUILeavesAnyLayer(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	ctx := context.Background()
	tenant := freshTenant(t, db, "d43-b")
	agentMeta, agentHeaders, agentFull, agentLegacy := uuid(t), uuid(t), uuid(t), uuid(t)
	for _, id := range []string{agentMeta, agentHeaders, agentFull, agentLegacy} {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.Agents{}).Register(ctx, sc, id, "ebpf-"+id[:8], "node", "", crypto.AgentSPIFFEID(tenant, id), []string{"collector", "ebpf"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	agentLogs, ctlLogs := &syncBuf{}, &syncBuf{}
	agentLog := slog.New(slog.NewJSONHandler(agentLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctlLog := slog.New(slog.NewJSONHandler(ctlLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	stack := startD43Stack(t, db, ctlLog)

	dir := t.TempDir()
	flowsPath := d43WriteJSON(t, dir, "flows.json", []map[string]any{
		{"source_address": "10.0.1.5", "source_port": 51002, "destination_address": "10.0.2.9", "destination_port": 8443,
			"network_transport": "tcp", "network_type": "ipv4", "bytes": 2048, "packets": 12, "direction": "egress", "state": "established"},
	})
	l7Path := d43WriteJSON(t, dir, "l7.json", []map[string]any{
		{"conn_id": 7, "kind": "request", "source_workload": "portal", "destination_workload": "records", "destination_port": 8443,
			"time_offset_ms": 0, "text": d43Request},
		{"conn_id": 7, "kind": "response", "time_offset_ms": 12,
			"text": "HTTP/1.1 201 Created\r\nSet-Cookie: sid=COOKIESECRETVALUE\r\nContent-Length: 0\r\n\r\n"},
	})

	// The three probectl agents, each on its own recorded bus.
	buses := map[string]*recordingBus{agentMeta: {}, agentHeaders: {}, agentFull: {}}
	runD43Agent(t, stack, tenant, agentMeta, ebpf.RedactMetadata, flowsPath, l7Path, buses[agentMeta], agentLog)
	runD43Agent(t, stack, tenant, agentHeaders, ebpf.RedactHeaders, flowsPath, l7Path, buses[agentHeaders], agentLog)
	runD43Agent(t, stack, tenant, agentFull, ebpf.RedactFull, flowsPath, l7Path, buses[agentFull], agentLog)

	var published []bus.Message
	for _, id := range []string{agentMeta, agentHeaders, agentFull} {
		msgs := buses[id].snapshot()
		if len(msgs) == 0 {
			t.Fatalf("agent %s published nothing (flows must still flow when L7 is refused)", id)
		}
		published = append(published, msgs...)
	}
	legacy := bus.Message{Topic: bus.EBPFFlowsTopic, Key: []byte(tenant), Value: legacyRecord(t, tenant, agentLegacy)}
	if got := findNeedles(legacy.Value); len(got) != len(d43Needles) {
		t.Fatalf("the hostile record must carry every needle (non-vacuity), carries %v", got)
	}

	// The control plane: one strip over the tenants' governance rows, the real
	// registry binding, and the real eBPF consumers with their stores.
	strip := NewL7IngestStrip(govern.NewPolicyStore(db.Pool()), false, ctlLog)
	binding := pipeline.NewRegistryBinding(db.Pool())
	ebpfRows := ebpfstore.NewMemory()
	topo := topology.NewMemoryStore()
	topoC := NewTopologyConsumer(nil, topo, ctlLog).WithTenantBinding(binding).WithEBPFStore(ebpfRows).WithL7IngestStrip(strip)
	detections := threat.NewDetectionStore(0)
	ndrC := NewNDRConsumer(nil, ndrEngine(t, nil), nil, ctlLog).WithTenantBinding(binding).withDetections(detections).WithL7IngestStrip(strip)
	postures := threat.NewPostureStore(0)
	tlsC := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}), ctlLog).WithTenantBinding(binding).WithL7IngestStrip(strip)

	var ingestOut bytes.Buffer
	for _, msg := range append(append([]bus.Message(nil), published...), legacy) {
		for name, handle := range map[string]func(context.Context, bus.Message, string) error{
			"topology": topoC.handleEBPFLane, "ndr": ndrC.handleEBPFBatchLane, "tls-posture": tlsC.handleLane,
		} {
			if err := handle(ctx, msg, ""); err != nil {
				t.Fatalf("%s consumer: %v", name, err)
			}
		}
		// The ingest output every consumer reads: the record after the door.
		batch, err := decodeEBPFBatch(ctx, strip, msg, "", false)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := proto.Marshal(batch)
		ingestOut.Write(out)
		js, _ := json.Marshal(batch)
		ingestOut.Write(js)
	}

	// Persisted rows: the eBPF store, the topology graph, the TLS posture and
	// detection read models, the agents' registry rows and the tenant's audit
	// chain.
	var persisted bytes.Buffer
	if _, err := ebpfRows.ExportTenant(ctx, tenant, &persisted); err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{topo.SnapshotAt(tenant, time.Now()), postures.List(tenant), detections.List(tenant)} {
		js, _ := json.Marshal(v)
		persisted.Write(js)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT row_to_json(a)::text FROM agents a`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			persisted.WriteString(s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{agenttransport.L7PostureAuditAction, ""} {
		js, _ := json.Marshal(auditActions(t, db, tenant, action))
		persisted.Write(js)
	}

	// A support bundle generated through the API, decompressed file by file.
	srv.log = ctlLog
	srv.WithL7IngestStrip(strip)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/diagnostics/bundle", nil)
	req.Header.Set("X-Probectl-Tenant", tenant)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("support bundle: %d %s", rec.Code, rec.Body)
	}
	files, err := support.ReadBundle(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var bundle bytes.Buffer
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		bundle.Write(files[n])
	}

	// The byte search.
	var busBytes bytes.Buffer
	for _, m := range published {
		busBytes.Write(m.Key)
		busBytes.Write(m.Value)
	}
	surfaces := []struct {
		name string
		hay  []byte
	}{
		{"published bus records (the probectl agents)", busBytes.Bytes()},
		{"agent logs", agentLogs.Bytes()},
		{"control-plane logs", ctlLogs.Bytes()},
		{"ingest output (what every consumer reads)", ingestOut.Bytes()},
		{"persisted rows", persisted.Bytes()},
		{"support bundle", bundle.Bytes()},
	}
	for _, s := range surfaces {
		if found := findNeedles(s.hay); len(found) > 0 {
			t.Errorf("D-43 LEAK — %s carry %v", s.name, found)
		}
	}
	// The bundle's own contract: no raw tenant, agent or workload identifier.
	for _, id := range []string{tenant, agentMeta, agentHeaders, agentFull, "exe:/opt/records/bin/records-api"} {
		if bytes.Contains(bundle.Bytes(), []byte(id)) {
			t.Errorf("D-43 LEAK — support bundle carries the identifier %q", id)
		}
	}

	// Non-vacuity: the pipeline really carried the call, the misconfigured
	// agents were really refused, the strip really worked, the bundle really
	// reports the posture.
	if !bytes.Contains(buses[agentMeta].snapshot()[0].Value, []byte("/contracts/{id}/drawings")) {
		t.Error("the metadata agent did not publish the templated call (vacuous run)")
	}
	if !bytes.Contains(ingestOut.Bytes(), []byte("/contracts/{id}/drawings")) {
		t.Error("the ingest output lost the templated call (vacuous run)")
	}
	for _, id := range []string{agentHeaders, agentFull} {
		for _, m := range buses[id].snapshot() {
			var b ebpfv1.FlowBatch
			if err := proto.Unmarshal(m.Value, &b); err != nil || len(b.GetL7Calls()) != 0 {
				t.Errorf("misconfigured agent %s published %d L7 calls under a metadata floor", id, len(b.GetL7Calls()))
			}
		}
	}
	postureState := func(id string) string {
		var raw []byte
		_ = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT l7_capture_posture FROM agents WHERE id = $1`, id).Scan(&raw)
		})
		var p store.L7CapturePosture
		_ = json.Unmarshal(raw, &p)
		return p.State + "/" + p.RedactionMode + "/" + p.RedactionFloor
	}
	for id, want := range map[string]string{
		agentMeta: "replaying/metadata/metadata", agentHeaders: "refused_floor/headers/metadata", agentFull: "refused_floor/full/metadata",
	} {
		if got := postureState(id); got != want {
			t.Errorf("agent %s posture = %s, want %s", id, got, want)
		}
	}
	if n := len(auditActions(t, db, tenant, agenttransport.L7PostureAuditAction)); n != 3 {
		t.Errorf("posture audit events = %d, want one per consented agent (3)", n)
	}
	counts := strip.Counts()
	if counts["query"] == 0 || counts["identifier_segment"] == 0 || counts[stripUnknownField] == 0 {
		t.Errorf("the ingest strip counted nothing (vacuous run): %v", counts)
	}
	var l7Section support.L7CaptureSummary
	if err := json.Unmarshal(files["l7-capture.json"], &l7Section); err != nil || len(l7Section.Agents) != 3 || l7Section.RedactionFloor != "metadata" {
		t.Errorf("bundle l7-capture section = %+v (%v)", l7Section, err)
	}
	if t.Failed() {
		t.Logf("D-43 regression (b) surfaces: %s", strings.Join(func() []string {
			out := []string{}
			for _, s := range surfaces {
				out = append(out, fmt.Sprintf("%s=%dB", s.name, len(s.hay)))
			}
			return out
		}(), ", "))
	}
}
