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
	"encoding/base64"
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

	"github.com/miekg/dns"
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

// The bytes D-43 regression test (b) hunts for. Every one is a value the
// fixtures (or the hostile producer) carry that must never reach a stored,
// logged or exported surface: a request body, a credential and two identity
// header values, a cookie, query-string values, the raw identifier path
// segment, the raw DNS question name (D-65), the DGA burst's raw names, the
// length-floor tenant's route, the headers tenant's query, and payload
// smuggled into an edge's l7_protocol. None is key-shaped (secret-scan safe).
var d43Needles = []string{
	"W56HZV-23-C-0123",              // the metadata tenant's raw contract-number path segment
	"QUERYSSN987",                   // query-string values
	"QUERYSESSION",                  //
	"HDRQUERYSECRET",                // the headers tenant's query value (never kept, even opted in)
	"credvalue-not-a-real-token",    // Authorization header value
	"pat.person@contractor.example", // identity header value
	"records.internal",              // Host header value
	"BODYCUI-CONTROLLED-7731",       // request body
	"COOKIESECRETVALUE",             // Set-Cookie value
	"48213.patients.example.com",    // the raw DNS question name
	"rendezvous-dga-",               // the DGA burst's raw first labels
	"LENGTHTENANT-ROUTE",            // a length-floor tenant's route: no call persists
	"EDGECUI-PROTOCOL-9911",         // payload smuggled into an edge's l7_protocol
	// D-65 R1: identifiers in cloud-provider (PSL private) and unlisted-TLD names
	"bucket-patient-48213", "acct48213", "cust-48213", "patient-48213",
	"w56hzv-23-c-0123", "records-48213", "host48213", "mrn48213",
}

// r1DNSNames are the names the review showed keeping identifiers (D-65 R1).
var r1DNSNames = []string{
	"bucket-patient-48213.s3.amazonaws.com", "acct48213.blob.core.windows.net",
	"cust-48213.azurewebsites.net", "patient-48213.github.io",
	"w56hzv-23-c-0123.internal", "records-48213.corp", "host48213.local", "mrn48213.lan",
}

// regulatedNeedles may not survive the regulated profile either: there only
// the registered domain of a DNS name is kept.
var regulatedNeedles = []string{"patients.example.com", "{id}.patients",
	// the headers tenant's opted-in values: under regulated its opt-in cannot apply
	"HDRSEG-77-X-0001", "77310.hdrzone", "hdrtenant-dga-"}

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
// the database-backed L7 policy, and a test CA that issues eBPF SVIDs.
type d43Stack struct {
	addr, caFile, dir string
	ca                *crypto.CA
}

func startD43Stack(t *testing.T, db *store.DB, ctlLog *slog.Logger, regulated bool) d43Stack {
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
	srv.WithL7Policy(agenttransport.NewL7Policy(db.Pool(), regulated))
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

// runD43Agent runs one real eBPF agent (fixture flows + an L7 fixture through
// the agent's capture boundary) against the control plane's policy channel.
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

func dnsMessage(t *testing.T, name string, response bool) string {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Id = 4242
	if response {
		m.Response = true
		m.Rcode = dns.RcodeSuccess
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// l7Fixture is one HTTP exchange plus one DNS exchange per name.
func l7Fixture(t *testing.T, dir, name, request string, dnsNames ...string) string {
	t.Helper()
	recs := []map[string]any{
		{"conn_id": 7, "kind": "request", "source_workload": "portal", "destination_workload": "records", "destination_port": 8443,
			"time_offset_ms": 0, "text": request},
		{"conn_id": 7, "kind": "response", "time_offset_ms": 12,
			"text": "HTTP/1.1 201 Created\r\nSet-Cookie: sid=COOKIESECRETVALUE\r\nContent-Length: 0\r\n\r\n"},
	}
	for i, n := range dnsNames {
		conn := 100 + i
		recs = append(recs,
			map[string]any{"conn_id": conn, "kind": "request", "source_workload": "portal", "destination_workload": "resolver", "destination_port": 53,
				"transport": "udp", "time_offset_ms": 20 + 4*i, "base64": dnsMessage(t, n, false)},
			map[string]any{"conn_id": conn, "kind": "response", "time_offset_ms": 22 + 4*i, "base64": dnsMessage(t, n, true)})
	}
	return d43WriteJSON(t, dir, name, recs)
}

// hostileRecord is what an outdated or hostile producer holding a tenant's bus
// credential could publish: full calls with query strings and identifiers,
// header/body bytes in fields the schema does not know, payload in an edge's
// l7_protocol, and a burst of generated DNS names (with the features an agent
// would compute, so the DGA detector fires and its summary is persisted).
func hostileRecord(t *testing.T, tenant, agentID, route, dnsName, dgaPrefix string, moreDNS ...string) []byte {
	t.Helper()
	calls := []*ebpfv1.L7Call{{
		TenantId: tenant, AgentId: agentID, Source: "portal", Destination: "records", DestinationPort: 8443,
		Protocol: "http1", Method: "POST", Status: "201", Resource: route,
	}, {
		TenantId: tenant, AgentId: agentID, Source: "portal", Destination: "resolver", DestinationPort: 53,
		Protocol: "dns", Method: "A", Status: "NOERROR", Resource: dnsName, DnsFeatures: testDNSFeatures(dnsName),
	}}
	for _, n := range moreDNS {
		calls = append(calls, &ebpfv1.L7Call{TenantId: tenant, AgentId: agentID, Source: "portal", Destination: "resolver",
			DestinationPort: 53, Protocol: "dns", Method: "A", Status: "NOERROR", Resource: n, DnsFeatures: testDNSFeatures(n)})
	}
	at := time.Now()
	for i := 0; i < 30; i++ {
		n := fmt.Sprintf("%sx%dq%dz.evil-rendezvous.example", dgaPrefix, i*7919, i*104729)
		calls = append(calls, &ebpfv1.L7Call{TenantId: tenant, AgentId: agentID, Source: "portal-dga", Destination: "resolver",
			DestinationPort: 53, Protocol: "dns", Method: "A", Status: "NOERROR", Resource: n,
			StartUnixNano: at.Add(time.Duration(i) * time.Second).UnixNano(), DnsFeatures: testDNSFeatures(n)})
	}
	batch := &ebpfv1.FlowBatch{
		Flows: []*ebpfv1.Flow{{TenantId: tenant, AgentId: agentID, Host: "legacy", SourceAddress: "10.9.0.1", DestinationAddress: "10.9.0.2",
			DestinationPort: 8443, NetworkTransport: "tcp", Bytes: 10, Packets: 1, ObservedAtUnixNano: at.UnixNano()}},
		Edges: []*ebpfv1.ServiceEdge{{TenantId: tenant, Source: "portal", Destination: "records", DestinationPort: 8443,
			NetworkTransport: "tcp", L7Protocol: "EDGECUI-PROTOCOL-9911 /patients/48213?ssn=QUERYSSN987", Connections: 1, Bytes: 10, Packets: 1,
			FirstSeenUnixNano: at.UnixNano(), LastSeenUnixNano: at.UnixNano()}},
		L7Calls: calls,
	}
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	extra, _ := proto.Marshal(&ebpfv1.L7Call{TenantId: tenant, AgentId: agentID, Protocol: "http1", Method: "GET", Status: "200", Resource: "/x"})
	extra = protowire.AppendBytes(protowire.AppendTag(extra, 90, protowire.BytesType),
		[]byte("Authorization: Bearer credvalue-not-a-real-token\r\nX-User-Email: pat.person@contractor.example\r\nHost: records.internal"))
	extra = protowire.AppendBytes(protowire.AppendTag(extra, 91, protowire.BytesType), []byte(`{"diagnosis":"BODYCUI-CONTROLLED-7731"} COOKIESECRETVALUE`))
	return protowire.AppendBytes(protowire.AppendTag(raw, 3, protowire.BytesType), extra)
}

func findNeedles(hay []byte, needles []string) []string {
	var found []string
	for _, n := range needles {
		if bytes.Contains(hay, []byte(n)) {
			found = append(found, n)
		}
	}
	return found
}

func registerD43Agent(t *testing.T, db *store.DB, tenant string) string {
	t.Helper()
	id := uuid(t)
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.Agents{}).Register(ctx, sc, id, "ebpf-"+id[:8], "node", "", crypto.EBPFSPIFFEID(tenant, id), []string{"collector", "ebpf"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// setFloor states a tenant's floor directly on its governance row (the core
// route is exercised in TestL7CapturePolicyCoreRealStack; here the regulated
// leg also needs a statement made before the profile changed).
func setFloor(t *testing.T, db *store.DB, tenant, mode string) {
	t.Helper()
	if err := govern.NewPolicyStore(db.Pool()).SetTenantL7CaptureRedaction(context.Background(), tenant, mode, "test",
		func(context.Context, tenancy.Scope) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// D-43 regression test (b), widened by refinement 3, review S8 and D-65. Per
// deployment profile (single, regulated) there are three tenants:
//   - meta: no statement (the metadata default). Three probectl eBPF agents
//     replay an HTTP and a DNS exchange through the real agent pipeline and
//     fetch the floor over the real mTLS agent channel: one in metadata mode,
//     two deliberately misconfigured with headers and full set locally.
//   - headers: opted into headers. Its agent captures literal routes (the
//     opt-in) — except under regulated, where the opt-in cannot apply.
//   - length: a length floor. Its metadata agent is refused.
//
// A hostile producer then publishes, for each tenant, full calls, header and
// body bytes in unknown fields, payload in an edge's l7_protocol, and a DGA
// burst, straight to the bus. Every record crosses the ingest door into the
// real topology, NDR and TLS-posture consumers and the eBPF store, and a
// support bundle is generated through the API. The byte search covers the bus
// records the probectl agents published, the agents' and the control plane's
// logs, the ingest output every consumer reads, every persisted row (eBPF
// store, topology graph, posture and detection read models, agents' registry
// rows, the tenants' audit chains) and the decompressed bundle.
func TestD43RegressionB_NoCUILeavesAnyLayer(t *testing.T) {
	for _, regulated := range []bool{false, true} {
		name := "single"
		if regulated {
			name = "regulated"
		}
		t.Run(name, func(t *testing.T) { runD43RegressionB(t, regulated) })
	}
}

func runD43RegressionB(t *testing.T, regulated bool) {
	srv, db := setupAPIServerWithLatest(t, nil)
	if regulated {
		srv.cfg.DeploymentProfile = "regulated"
	}
	ctx := context.Background()
	tMeta, tHeaders, tLength := freshTenant(t, db, "d43-b-meta"), freshTenant(t, db, "d43-b-hdr"), freshTenant(t, db, "d43-b-len")
	setFloor(t, db, tHeaders, "headers")
	setFloor(t, db, tLength, "length")
	agentMeta, agentHeaders, agentFull := registerD43Agent(t, db, tMeta), registerD43Agent(t, db, tMeta), registerD43Agent(t, db, tMeta)
	agentHdr, agentLen := registerD43Agent(t, db, tHeaders), registerD43Agent(t, db, tLength)
	hostileIDs := map[string]string{tMeta: registerD43Agent(t, db, tMeta), tHeaders: registerD43Agent(t, db, tHeaders), tLength: registerD43Agent(t, db, tLength)}

	agentLogs, ctlLogs := &syncBuf{}, &syncBuf{}
	agentLog := slog.New(slog.NewJSONHandler(agentLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctlLog := slog.New(slog.NewJSONHandler(ctlLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	stack := startD43Stack(t, db, ctlLog, regulated)

	dir := t.TempDir()
	flowsPath := d43WriteJSON(t, dir, "flows.json", []map[string]any{
		{"source_address": "10.0.1.5", "source_port": 51002, "destination_address": "10.0.2.9", "destination_port": 8443,
			"network_transport": "tcp", "network_type": "ipv4", "bytes": 2048, "packets": 12, "direction": "egress", "state": "established"},
	})
	metaL7 := l7Fixture(t, dir, "l7-meta.json", d43Request, append([]string{"48213.patients.example.com"}, r1DNSNames...)...)
	// The headers tenant opted in: its literal route and DNS name may persist
	// (single profile), so they are its own values, not needles.
	hdrL7 := l7Fixture(t, dir, "l7-hdr.json", "GET /hdr/HDRSEG-77-X-0001/view?k=HDRQUERYSECRET HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "77310.hdrzone.example.com")
	lenL7 := l7Fixture(t, dir, "l7-len.json", "GET /LENGTHTENANT-ROUTE/x HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "48213.patients.example.com")

	buses := map[string]*recordingBus{}
	for _, a := range []struct{ tenant, id, mode, fixture string }{
		{tMeta, agentMeta, ebpf.RedactMetadata, metaL7},
		{tMeta, agentHeaders, ebpf.RedactHeaders, metaL7},
		{tMeta, agentFull, ebpf.RedactFull, metaL7},
		{tHeaders, agentHdr, ebpf.RedactHeaders, hdrL7},
		{tLength, agentLen, ebpf.RedactMetadata, lenL7},
	} {
		buses[a.id] = &recordingBus{}
		runD43Agent(t, stack, a.tenant, a.id, a.mode, flowsPath, a.fixture, buses[a.id], agentLog)
	}
	var published []bus.Message
	for id, b := range buses {
		msgs := b.snapshot()
		if len(msgs) == 0 {
			t.Fatalf("agent %s published nothing (flows must still flow when L7 is refused)", id)
		}
		published = append(published, msgs...)
	}
	var hostile []bus.Message
	for tenant, id := range hostileIDs {
		route, dnsName, dga, more := "/contracts/W56HZV-23-C-0123/drawings?ssn=QUERYSSN987&session=QUERYSESSION", "48213.patients.example.com", "rendezvous-dga-", r1DNSNames
		switch tenant {
		case tLength:
			route, more = "/LENGTHTENANT-ROUTE/x", nil
		case tHeaders:
			route, dnsName, dga, more = "/hdr/HDRSEG-77-X-0001/view?k=HDRQUERYSECRET", "77310.hdrzone.example.com", "hdrtenant-dga-", nil
		}
		m := bus.Message{Topic: bus.EBPFFlowsTopic, Key: []byte(tenant), Value: hostileRecord(t, tenant, id, route, dnsName, dga, more...)}
		hostile = append(hostile, m)
	}
	for _, h := range hostile {
		if got := findNeedles(h.Value, []string{"BODYCUI-CONTROLLED-7731", "EDGECUI-PROTOCOL-9911"}); len(got) != 2 {
			t.Fatalf("the hostile record must carry its needles (non-vacuity), carries %v", got)
		}
	}

	// The control plane: one strip over the tenants' governance rows behind
	// the real registry binding, and the real eBPF consumers with their stores.
	binding := pipeline.NewRegistryBinding(db.Pool())
	strip := NewL7IngestStrip(govern.NewPolicyStore(db.Pool()), regulated, ctlLog).WithTenantBinding(binding)
	ebpfRows := ebpfstore.NewMemory()
	topo := topology.NewMemoryStore()
	topoC := NewTopologyConsumer(nil, topo, ctlLog).WithTenantBinding(binding).WithEBPFStore(ebpfRows).WithL7IngestStrip(strip)
	detections := threat.NewDetectionStore(0)
	ndrC := NewNDRConsumer(nil, ndrEngine(t, nil), nil, ctlLog).WithTenantBinding(binding).withDetections(detections).WithL7IngestStrip(strip)
	postures := threat.NewPostureStore(0)
	tlsC := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}), ctlLog).WithTenantBinding(binding).WithL7IngestStrip(strip)

	ingestOut := map[string]*bytes.Buffer{"all": {}}
	for _, msg := range append(append([]bus.Message(nil), published...), hostile...) {
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
		js, _ := json.Marshal(batch)
		ingestOut["all"].Write(out)
		ingestOut["all"].Write(js)
		for _, c := range batch.GetL7Calls() {
			if ingestOut[c.GetTenantId()] == nil {
				ingestOut[c.GetTenantId()] = &bytes.Buffer{}
			}
			cj, _ := json.Marshal(c)
			ingestOut[c.GetTenantId()].Write(cj)
		}
	}

	// Persisted rows, for every tenant.
	var persisted bytes.Buffer
	for _, tenant := range []string{tMeta, tHeaders, tLength} {
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
		js, _ := json.Marshal(auditActions(t, db, tenant, ""))
		persisted.Write(js)
	}

	// A support bundle per tenant, generated through the API, decompressed.
	srv.log = ctlLog
	srv.WithL7IngestStrip(strip)
	var bundle bytes.Buffer
	var metaSection support.L7CaptureSummary
	for _, tenant := range []string{tMeta, tHeaders, tLength} {
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
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			bundle.Write(files[n])
		}
		if tenant == tMeta {
			_ = json.Unmarshal(files["l7-capture.json"], &metaSection)
		}
	}

	// The byte search.
	var busBytes bytes.Buffer
	for _, m := range published {
		busBytes.Write(m.Key)
		busBytes.Write(m.Value)
	}
	needles := append([]string(nil), d43Needles...)
	if regulated {
		needles = append(needles, regulatedNeedles...)
	}
	surfaces := []struct {
		name string
		hay  []byte
	}{
		{"published bus records (the probectl agents)", busBytes.Bytes()},
		{"agent logs", agentLogs.Bytes()},
		{"control-plane logs", ctlLogs.Bytes()},
		{"ingest output (what every consumer reads)", ingestOut["all"].Bytes()},
		{"persisted rows", persisted.Bytes()},
		{"support bundle", bundle.Bytes()},
	}
	for _, s := range surfaces {
		if found := findNeedles(s.hay, needles); len(found) > 0 {
			t.Errorf("D-43 LEAK — %s carry %v", s.name, found)
		}
	}
	// The bundle's own contract: no raw tenant, agent or workload identifier.
	for _, id := range []string{tMeta, agentMeta, agentHeaders, agentFull, "exe:/opt/records/bin/records-api"} {
		if bytes.Contains(bundle.Bytes(), []byte(id)) {
			t.Errorf("D-43 LEAK — support bundle carries the identifier %q", id)
		}
	}
	// A length-floor tenant persists no L7 call at all.
	if b := ingestOut[tLength]; b != nil && b.Len() > 0 {
		t.Errorf("D-43 LEAK — the length tenant's calls came out of the door: %s", b.Bytes())
	}

	// Non-vacuity: the pipeline really carried each case.
	metaBus := buses[agentMeta].snapshot()[0].Value
	wantDNS := []string{"{id}.patients.example.com", "{id}.s3.amazonaws.com", "{id}.github.io", "{id}.internal", "{id}.lan"}
	if regulated {
		wantDNS = []string{"example.com", "amazonaws.com", "github.io", "{id}.internal", "{id}.lan"}
	}
	for _, want := range append([]string{"/contracts/{id}/drawings"}, wantDNS...) {
		if !bytes.Contains(metaBus, []byte(want)) {
			t.Errorf("the metadata agent did not publish %q (vacuous run)", want)
		}
		if !bytes.Contains(ingestOut["all"].Bytes(), []byte(want)) {
			t.Errorf("the ingest output lost %q (vacuous run)", want)
		}
	}
	hdrBus := buses[agentHdr].snapshot()[0].Value
	if regulated {
		if bytes.Contains(hdrBus, []byte("HDRSEG-77-X-0001")) {
			t.Error("the regulated profile let the headers opt-in through at the agent")
		}
	} else if !bytes.Contains(hdrBus, []byte("/hdr/HDRSEG-77-X-0001/view")) {
		t.Error("the headers opt-in did not keep its literal route (vacuous run)")
	}
	for _, id := range []string{agentHeaders, agentFull, agentLen} {
		for _, m := range buses[id].snapshot() {
			var b ebpfv1.FlowBatch
			if err := proto.Unmarshal(m.Value, &b); err != nil || len(b.GetL7Calls()) != 0 {
				t.Errorf("refused agent %s published %d L7 calls", id, len(b.GetL7Calls()))
			}
		}
	}
	if !bytes.Contains(ingestOut["all"].Bytes(), []byte(`"l7_protocol":"other"`)) {
		t.Error("the hostile edge's l7_protocol was not clamped (vacuous run)")
	}
	dga := false
	for _, d := range detections.List(tMeta) {
		dga = dga || d.Kind == "ndr.dns_dga"
	}
	if !dga {
		t.Error("the DGA detector lost its signal under D-65 minimization")
	}
	postureState := func(tenant, id string) string {
		var raw []byte
		_ = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT l7_capture_posture FROM agents WHERE id = $1`, id).Scan(&raw)
		})
		var p store.L7CapturePosture
		_ = json.Unmarshal(raw, &p)
		return p.State + "/" + p.RedactionMode + "/" + p.RedactionFloor
	}
	hdrWant := "replaying/headers/headers"
	if regulated {
		hdrWant = "refused_floor/headers/metadata"
	}
	for _, c := range []struct{ tenant, id, want string }{
		{tMeta, agentMeta, "replaying/metadata/metadata"}, {tMeta, agentHeaders, "refused_floor/headers/metadata"},
		{tMeta, agentFull, "refused_floor/full/metadata"}, {tHeaders, agentHdr, hdrWant}, {tLength, agentLen, "refused_floor/metadata/length"},
	} {
		if got := postureState(c.tenant, c.id); got != c.want {
			t.Errorf("agent %s posture = %s, want %s", c.id, got, c.want)
		}
	}
	if n := len(auditActions(t, db, tMeta, agenttransport.L7PostureAuditAction)); n != 3 {
		t.Errorf("meta tenant posture audit events = %d, want one per consented agent (3)", n)
	}
	counts := strip.Counts()
	for _, f := range []string{"query", "identifier_segment", stripUnknownField, "enum_field", stripCallDropped} {
		if counts[f] == 0 {
			t.Errorf("the ingest strip counted no %s (vacuous run): %v", f, counts)
		}
	}
	if len(metaSection.Agents) != 3 || metaSection.RedactionFloor != "metadata" {
		t.Errorf("bundle l7-capture section = %+v", metaSection)
	}
	if t.Failed() {
		parts := []string{}
		for _, s := range surfaces {
			parts = append(parts, fmt.Sprintf("%s=%dB", s.name, len(s.hay)))
		}
		t.Logf("D-43 regression (b) surfaces: %s", strings.Join(parts, ", "))
	}
}
