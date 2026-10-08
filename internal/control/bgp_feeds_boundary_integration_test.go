// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"golang.org/x/net/websocket"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestBGPAnalyzerFeedBoundaryRealStack is the real-stack receipt for
// CLM-BGP-FEEDS ("The analyzer fetches only RPKI VRP data; MRT is
// bring-your-own local input; RIS Live reads RIPE's public websocket").
//
// It builds and runs the SHIPPED sidecar — `probectl-control bgp-analyzer`,
// which supervises the real Python analyzer — once per tenant, publishing to
// real Kafka on each tenant's lane, consumed by the strict BGP incident
// consumer into PostgreSQL, read back through /v1/bgp/events. RIPE's RIS Live
// and the RPKI validator are local stand-ins that speak their real protocols
// (a TLS websocket at wss://ris-live.ripe.net/v1/ws/ and an HTTPS VRP export),
// reached only through a recording HTTPS proxy, with the analyzer trusting only
// the test CA. A Python audit hook records every socket the analyzer opens and
// every file it reads. It proves:
//
//   - live mode reads RIPE's websocket — the hard-coded ris-live.ripe.net:443,
//     path /v1/ws/, subscribed to exactly the monitored prefix — plus the
//     configured VRP export, and nothing else;
//   - MRT mode reads the operator's local file and makes no network call but
//     the VRP fetch: the feed is bring-your-own;
//   - the fetched VRPs are applied (both announcements are RPKI-invalid), and
//     each tenant's events reach only that tenant.
func TestBGPAnalyzerFeedBoundaryRealStack(t *testing.T) {
	ctx := context.Background()
	python := os.Getenv("PROBECTL_TEST_ANALYZER_PYTHON")
	if python == "" {
		python = "python3"
	}
	if out, err := exec.Command(python, "-c", "import websockets, structlog").CombinedOutput(); err != nil {
		testsupport.SkipOrFatal(t, "the analyzer runtime (analyzer/requirements.lock) is not installed for %s: %v %s", python, err, out)
	}
	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — the feed-boundary receipt needs a real bus")
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "probectl-control")
	if out, err := exec.Command("go", "build", "-o", binary, filepath.Join(repoRoot, "cmd", "probectl-control")).CombinedOutput(); err != nil {
		t.Fatalf("build the shipped control binary: %v\n%s", err, out)
	}

	db := changeDB(t)
	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	log := quietLog()
	tenantA, tenantB, tenantC := freshTenant(t, db, "feeds-live"), freshTenant(t, db, "feeds-mrt"), freshTenant(t, db, "feeds-decoy")
	lanes := map[string]string{}
	laneOf := map[string]string{}
	var laneTopics []string
	for _, tenant := range []string{tenantA, tenantB, tenantC} {
		ns, err := store.NewTenants(db.Pool()).BusNamespace(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		lanes[ns], laneOf[tenant] = tenant, ns
		topic, err := bus.TopicFor(ns, bus.BGPEventsTopic)
		if err != nil {
			t.Fatal(err)
		}
		laneTopics = append(laneTopics, topic)
	}
	if _, err := b.EnsureTopics(ctx, laneTopics, 1, -1); err != nil {
		t.Fatalf("create tenant lanes: %v", err)
	}
	go func() {
		_ = NewBGPIncidentConsumer(b, BuildCorrelator(db.Pool(), 10*time.Minute, log), log).
			WithNamespaceTenants(lanes).WithStrictTenantLanes(true).Run(runCtx)
	}()
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "session", SessionTTL: time.Hour, SessionHMACKey: fcRandom(t)}
	srv := New(cfg, log, db, db.Pool(), nil, nil).WithTenantStatus(NewTenantStatusCache(db.Pool(), 0))
	h := srv.Handler()
	alice, bob, dave := sessionAdmin(t, db, srv, h, tenantA, "alice"), sessionAdmin(t, db, srv, h, tenantB, "bob"), sessionAdmin(t, db, srv, h, tenantC, "dave")

	// The outside world: RIPE's RIS Live and an RPKI validator, as stand-ins
	// that speak their protocols over TLS under a CA only the analyzer trusts.
	ca, err := crypto.GenerateCA("bgp-feeds-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := fcWrite(t, t.TempDir(), "ca.pem", ca.CertPEM())
	ris := newRISLiveStandIn(t, ca)
	vrp := newVRPStandIn(t, ca)
	proxy := newRecordingProxy(t, map[string]string{"ris-live.ripe.net:443": ris.addr, "rpki.example.test:443": vrp.addr})

	run := func(label, tenant, source, sourceFile, prefix string, expectedOrigin int) (*exec.Cmd, string) {
		t.Helper()
		dir := t.TempDir()
		auditLog := filepath.Join(dir, "audit.jsonl")
		fcWrite(t, dir, "sitecustomize.py", []byte(fmt.Sprintf(pythonAuditHook, auditLog)))
		cfgBody, err := json.Marshal(map[string]any{
			"tenant_id": tenant, "collector": "rrc00",
			"monitored_prefixes": []map[string]any{{"prefix": prefix, "expected_origins": []int{expectedOrigin}}},
			"rpki_vrp_url":       "https://rpki.example.test/vrps.json",
		})
		if err != nil {
			t.Fatal(err)
		}
		env := []string{
			"PATH=" + os.Getenv("PATH"),
			"PROBECTL_BGP_ANALYZER_CONFIG=" + fcWrite(t, dir, "analyzer.json", cfgBody),
			"PROBECTL_BGP_ANALYZER_SOURCE=" + source,
			"PROBECTL_BGP_ANALYZER_PYTHON=" + python,
			"PROBECTL_BGP_ANALYZER_BUS_NAMESPACE=" + laneOf[tenant],
			"PROBECTL_BUS_MODE=kafka", "PROBECTL_BUS_BROKERS=" + strings.Join(brokers, ","), "PROBECTL_BUS_ALLOW_PLAINTEXT=true",
			"PYTHONPATH=" + filepath.Join(repoRoot, "analyzer") + string(os.PathListSeparator) + dir,
			"SSL_CERT_FILE=" + caFile,
			"HTTPS_PROXY=http://" + proxy.addr, "https_proxy=http://" + proxy.addr,
			"PROBECTL_LOG_LEVEL=info",
		}
		if sourceFile != "" {
			env = append(env, "PROBECTL_BGP_ANALYZER_SOURCE_FILE="+sourceFile)
		}
		proxy.label(label)
		cmd := exec.Command(binary, "bgp-analyzer")
		cmd.Env = env
		// Its own process group, so stopping it also stops the Python child
		// that holds its output pipe; WaitDelay bounds the pipe drain.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.WaitDelay = 5 * time.Second
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("%s analyzer output:\n%s", label, out.String())
			}
		})
		if err := cmd.Start(); err != nil {
			t.Fatalf("start %s analyzer: %v", label, err)
		}
		return cmd, auditLog
	}

	// MRT: the operator's own local file. A finite run.
	mrtFile := fcWrite(t, t.TempDir(), "routes.mrt", mrtUpdateAS4("198.51.100.0/24", []uint32{64511, 64500, 65552}))
	mrtCmd, mrtAudit := run("mrt", tenantB, "mrt", mrtFile, "198.51.100.0/24", 64497)
	if err := mrtCmd.Wait(); err != nil {
		t.Fatalf("mrt analyzer exited: %v", err)
	}
	// Live: RIPE's websocket. Runs until stopped.
	liveCmd, liveAudit := run("live", tenantA, "ris-live", "", "192.0.2.0/24", 64496)
	t.Cleanup(func() { stopAnalyzer(liveCmd) })

	liveEvent := awaitBGPEvent(t, alice, "192.0.2.0/24")
	mrtEvent := awaitBGPEvent(t, bob, "198.51.100.0/24")
	stopAnalyzer(liveCmd)

	// The VRPs were fetched and applied: both announcements are RPKI-invalid.
	for name, ev := range map[string]bgpEventItem{"live": liveEvent, "mrt": mrtEvent} {
		if ev.Attributes["rpki_status"] != "RPKI_STATUS_INVALID" {
			t.Errorf("%s event rpki_status = %q, want RPKI_STATUS_INVALID from the fetched VRPs: %+v", name, ev.Attributes["rpki_status"], ev)
		}
	}
	if got := vrp.hits(); got != 2 {
		t.Errorf("VRP export fetched %d times, want once per analyzer run (2)", got)
	}

	// Live mode: RIPE's websocket and the VRP export, nothing else.
	if got := proxy.targets("live"); !sameSet(got, []string{"ris-live.ripe.net:443", "rpki.example.test:443"}) {
		t.Errorf("live analyzer reached %v, want exactly RIS Live and the VRP export", got)
	}
	if path, subs := ris.observed(); path != "/v1/ws/" || len(subs) != 1 ||
		!strings.Contains(subs[0], `"type": "ris_subscribe"`) || !strings.Contains(subs[0], `"prefix": "192.0.2.0/24"`) {
		t.Errorf("RIS Live session = path %q subscriptions %q, want /v1/ws/ subscribed to the monitored prefix only", path, subs)
	}
	// MRT mode: the local file, and no network but the VRP export.
	if got := proxy.targets("mrt"); !sameSet(got, []string{"rpki.example.test:443"}) {
		t.Errorf("mrt analyzer reached %v, want only the VRP export", got)
	}
	if !auditedOpen(t, mrtAudit, mrtFile) {
		t.Errorf("mrt analyzer never read the operator's MRT file %s", mrtFile)
	}
	// Every socket either analyzer opened went to the proxy: there is no
	// side channel around the recorded boundary.
	for name, logFile := range map[string]string{"live": liveAudit, "mrt": mrtAudit} {
		for _, addr := range auditedConnects(t, logFile) {
			if !strings.Contains(addr, proxy.port) {
				t.Errorf("%s analyzer opened a socket to %s, outside the recorded proxy", name, addr)
			}
		}
	}

	// Scoping: each tenant sees only its own feed's events.
	if events := alice.text(t, "/v1/bgp/events?limit=100"); strings.Contains(events, "198.51.100.0/24") {
		t.Errorf("the live tenant sees the MRT tenant's route: %s", events)
	}
	if events := bob.text(t, "/v1/bgp/events?limit=100"); strings.Contains(events, "192.0.2.0/24") {
		t.Errorf("the MRT tenant sees the live tenant's route: %s", events)
	}
	if events := dave.text(t, "/v1/bgp/events?limit=100"); strings.Contains(events, "/24") {
		t.Errorf("a tenant with no analyzer has BGP events: %s", events)
	}
}

// stopAnalyzer asks the sidecar to stop (it then stops its Python child), and
// kills the whole process group if it has not exited in time.
func stopAnalyzer(cmd *exec.Cmd) {
	if cmd.ProcessState != nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
}

// pythonAuditHook is a sitecustomize module that logs every socket connect
// and file open of the analyzer process (PEP 578 audit events).
const pythonAuditHook = `import json, os, sys
_LOG = open(%q, "a", buffering=1, encoding="utf-8")
def _audit(event, args):
    try:
        if event == "socket.connect":
            _LOG.write(json.dumps({"event": event, "address": repr(args[1])}) + "\n")
        elif event == "open" and isinstance(args[0], (str, bytes)):
            _LOG.write(json.dumps({"event": event, "path": os.fsdecode(args[0]), "mode": str(args[1])}) + "\n")
    except Exception:
        pass
sys.addaudithook(_audit)
`

type auditEntry struct {
	Event   string `json:"event"`
	Address string `json:"address"`
	Path    string `json:"path"`
	Mode    string `json:"mode"`
}

func readAudit(t *testing.T, logFile string) []auditEntry {
	t.Helper()
	f, err := os.Open(logFile)
	if err != nil {
		t.Fatalf("the analyzer's audit hook never ran (%v): the boundary cannot be observed", err)
	}
	defer f.Close()
	var out []auditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e auditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

func auditedConnects(t *testing.T, logFile string) []string {
	t.Helper()
	var out []string
	for _, e := range readAudit(t, logFile) {
		if e.Event == "socket.connect" {
			out = append(out, e.Address)
		}
	}
	return out
}

func auditedOpen(t *testing.T, logFile, path string) bool {
	t.Helper()
	for _, e := range readAudit(t, logFile) {
		if e.Event == "open" && e.Path == path && strings.Contains(e.Mode, "r") {
			return true
		}
	}
	return false
}

func awaitBGPEvent(t *testing.T, u *fcUser, prefix string) bgpEventItem {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		var out struct {
			Items []bgpEventItem `json:"items"`
		}
		fcJSON(t, []byte(u.text(t, "/v1/bgp/events?limit=100")), &out)
		for _, it := range out.Items {
			if it.Prefix == prefix {
				return it
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("no BGP event for %s reached the tenant", prefix)
	return bgpEventItem{}
}

func sameSet(got, want []string) bool {
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	if len(seen) != len(want) {
		return false
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}

// mrtUpdateAS4 is one RFC 6396 BGP4MP_MESSAGE_AS4 record carrying a BGP
// UPDATE that announces prefix along asPath — the operator's local MRT file.
func mrtUpdateAS4(prefix string, asPath []uint32) []byte {
	ip, network, _ := net.ParseCIDR(prefix)
	bits, _ := network.Mask.Size()
	nlri := append([]byte{byte(bits)}, ip.To4()[:(bits+7)/8]...)
	seg := []byte{2, byte(len(asPath))} // AS_SEQUENCE
	for _, as := range asPath {
		seg = binary.BigEndian.AppendUint32(seg, as)
	}
	attrs := append([]byte{0x40, 2, byte(len(seg))}, seg...) // well-known transitive AS_PATH
	update := binary.BigEndian.AppendUint16(nil, 0)          // no withdrawals
	update = binary.BigEndian.AppendUint16(update, uint16(len(attrs)))
	update = append(append(update, attrs...), nlri...)
	msg := bytes.Repeat([]byte{0xff}, 16)
	msg = binary.BigEndian.AppendUint16(msg, uint16(19+len(update)))
	msg = append(append(msg, 2), update...)               // type 2 = UPDATE
	body := binary.BigEndian.AppendUint32(nil, asPath[0]) // peer AS
	body = binary.BigEndian.AppendUint32(body, 0)         // local AS
	body = binary.BigEndian.AppendUint16(body, 0)         // interface index
	body = binary.BigEndian.AppendUint16(body, 1)         // AFI IPv4
	body = append(body, net.ParseIP("192.0.2.1").To4()...)
	body = append(body, net.ParseIP("192.0.2.2").To4()...)
	body = append(body, msg...)
	rec := binary.BigEndian.AppendUint32(nil, uint32(time.Now().Unix()))
	rec = binary.BigEndian.AppendUint16(rec, 16) // BGP4MP
	rec = binary.BigEndian.AppendUint16(rec, 4)  // BGP4MP_MESSAGE_AS4
	rec = binary.BigEndian.AppendUint32(rec, uint32(len(body)))
	return append(rec, body...)
}

// tlsStandIn serves handler over TLS as host, under ca.
func tlsStandIn(t *testing.T, ca *crypto.CA, host string, handler http.Handler) *httptest.Server {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueServerCert(host, []string{host}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// risLiveStandIn speaks the RIS Live protocol: it accepts the websocket at
// /v1/ws/, records the subscriptions, and streams one UPDATE for 192.0.2.0/24
// from an unexpected origin.
type risLiveStandIn struct {
	addr string
	mu   sync.Mutex
	path string
	subs []string
}

func newRISLiveStandIn(t *testing.T, ca *crypto.CA) *risLiveStandIn {
	t.Helper()
	s := &risLiveStandIn{}
	ws := websocket.Server{
		// The RIS Live client sends no Origin header; accept it as RIPE does.
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(conn *websocket.Conn) {
			s.mu.Lock()
			s.path = conn.Request().URL.Path
			s.mu.Unlock()
			var sub string
			if err := websocket.Message.Receive(conn, &sub); err != nil {
				return
			}
			s.mu.Lock()
			s.subs = append(s.subs, sub)
			s.mu.Unlock()
			if err := websocket.Message.Send(conn, risUpdate("192.0.2.0/24", 65551)); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, conn) // hold the session open like RIPE does
		},
	}
	srv := tlsStandIn(t, ca, "ris-live.ripe.net", ws)
	s.addr = srv.Listener.Addr().String()
	return s
}

func (s *risLiveStandIn) observed() (string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path, append([]string(nil), s.subs...)
}

// vrpStandIn is an RPKI validator's JSON VRP export over HTTPS.
type vrpStandIn struct {
	addr string
	mu   sync.Mutex
	n    int
}

func newVRPStandIn(t *testing.T, ca *crypto.CA) *vrpStandIn {
	t.Helper()
	v := &vrpStandIn{}
	srv := tlsStandIn(t, ca, "rpki.example.test", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		v.mu.Lock()
		v.n++
		v.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"metadata":{"generated":0},"roas":[`+
			`{"prefix":"192.0.2.0/24","maxLength":24,"asn":"AS64496","ta":"test"},`+
			`{"prefix":"198.51.100.0/24","maxLength":24,"asn":"AS64497","ta":"test"}]}`)
	}))
	v.addr = srv.Listener.Addr().String()
	return v
}

func (v *vrpStandIn) hits() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.n
}

// recordingProxy is an HTTPS (CONNECT) proxy that records every target per
// run label, tunnels the allowed ones to their stand-ins, and refuses the rest.
type recordingProxy struct {
	addr, port string
	routes     map[string]string
	mu         sync.Mutex
	current    string
	seen       map[string][]string
}

func newRecordingProxy(t *testing.T, routes map[string]string) *recordingProxy {
	t.Helper()
	p := &recordingProxy{routes: routes, seen: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(srv.Close)
	p.addr = srv.Listener.Addr().String()
	_, p.port, _ = net.SplitHostPort(p.addr)
	return p
}

func (p *recordingProxy) label(l string) {
	p.mu.Lock()
	p.current = l
	p.mu.Unlock()
}

func (p *recordingProxy) targets(l string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen[l]...)
}

func (p *recordingProxy) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.seen[p.current] = append(p.seen[p.current], r.Host)
	backend, ok := p.routes[r.Host]
	p.mu.Unlock()
	if r.Method != http.MethodConnect || !ok {
		http.Error(w, "refused by the recording proxy", http.StatusForbidden)
		return
	}
	upstream, err := net.Dial("tcp", backend)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
	go func() { _, _ = io.Copy(client, upstream); _ = client.Close() }()
}
