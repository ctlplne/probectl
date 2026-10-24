// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package ai_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// The lab's routing plan. A's service listens on loopback, so A's address
// block is the loopback /24 its service address sits in; B's block is from
// the documentation range. Every ASN is from the documentation or private
// ranges.
const (
	collectorASN = 64511 // the lab route collector's peer
	upstreamASN  = 65010 // "the internet": the upstream on every path

	prefixA   = "127.0.0.0/24" // tenant A's address block, holding its service
	originA   = 64500          // ...the AS that should originate it
	hijackerA = 65021          // ...and the AS that hijacks it

	prefixB    = "198.51.100.0/24" // tenant B's block
	originB    = 64501
	noTransitB = 64666 // must never carry B's traffic: seeing it is a leak

	labCollector = "lab-rrc"
	serviceHost  = "127.0.0.1"
	evalInterval = 2 * time.Second
	probeMetric  = "probectl_probe_success"
)

// TestAIRootCauseRealStack is the real-stack receipt for AI root-cause
// analysis and the telemetry Explorer (F13): an MSP's two tenants each have a
// genuinely different fault in their own stores, and each asks "why?"
// through the public API, the CLI and the rendered Ask page. Every answer
// is the shipped analyzer's over the shipped stores, every citation is
// followed back to the record it names, and nothing of the other tenant's
// appears in an answer, its evidence or its reasoning trace.
//
// The stack is the shipped control plane and agent on the four-store profile
// (shipped.Start): PostgreSQL behind the least-privilege serve login,
// Kafka with strict tenant lanes, ClickHouse with the reader credential,
// Prometheus as the TSDB, TLS everywhere, Dex as the IdP (production session
// auth in Chromium) and an MSP license. A is pooled, B hybrid. The AI model
// is the deployment default, the builtin deterministic synthesizer, and
// HTTPS_PROXY/HTTP_PROXY name a recording proxy that forwards nothing: any
// outbound call the control plane makes off this host lands there.
//
// The planes, each produced by the shipped collector a published receipt
// already proves:
//
//   - Synthetic (F4/F8): each tenant's shipped agent runs a TCP test against
//     the tenant's own service on 127.0.0.1. Both services share that
//     address, so a read that loses its tenant scope returns the other
//     tenant's probes under the same server_address. Results land in
//     Prometheus; each tenant's alert rule (probe success < 1) is evaluated
//     by the shipped evaluator, and a firing alert is correlated into an
//     incident in PostgreSQL.
//   - BGP (F6): each tenant's shipped analyzer sidecar (probectl-control
//     bgp-analyzer, the Python analyzer under the Go tenant-bound bridge)
//     reads an MRT file of the lab collector with that tenant's own watch
//     config and publishes on the tenant's lane; the BGP consumer correlates
//     each anomaly into the tenant's incidents, the topology consumer folds it
//     into the tenant's graph. The MRT (RFC 6396 TABLE_DUMP_V2 baseline plus a
//     BGP4MP_MESSAGE_AS4 UPDATE) is encoded by this receipt: F6 proves real
//     BGP speakers produce it; this receipt is about what the analyzer does
//     with the stores afterwards.
//   - Path (F3): A traces its service from the control plane; the round lands
//     in ClickHouse's path tables, read back through the reader login.
//
// The faults:
//
//   - A: its block is hijacked (origin AS64500 -> AS65021), then its service
//     goes down. Cause before symptom, as in life: the hijack opens A's
//     incident on the prefix, and the outage alert on 127.0.0.1 joins it
//     (the IP is inside the prefix). One incident, two planes.
//
//   - B: its block leaks through no-transit AS64666; its service stays up.
//     One incident, one plane.
//
//     1. Two tenants, agents, tests and rules; each probe is up in Prometheus.
//     2. Faults injected; the correlator leaves exactly one tenant-scoped
//     incident per tenant fault, of the planes it touched; as the app role a
//     predicate-free count of the incidents table scoped to a tenant is
//     exactly its own.
//     3. RCA: A asks "Why is the service at 127.0.0.1 failing?" through
//     POST /v1/ai/ask and `probectl ai ask`; B asks why its prefix routes
//     through AS64666 the same two ways. Each answer was synthesized by the
//     builtin adapter locally with no egress consent needed; its root cause
//     is grounded, names the injected fault, and cites evidence that resolves
//     to a real record in the tenant's own stores: an incident signal (GET
//     /v1/incidents/{id}), and behind it the BGP event (GET /v1/bgp/events);
//     a probe series in Prometheus with its live value; a node of the
//     tenant's topology (GET /v1/topology). Every finding's citation names
//     an evidence item of the same answer. No answer holds any identifier,
//     prefix or ASN of the other tenant's.
//     4. Explorer: POST /v1/explorer/query and `probectl explorer query` read
//     the path plane (A's traced round from ClickHouse; B, which traced
//     nothing, gets no rows) and the topology plane (each tenant's own
//     routing edges only).
//     5. Tenant first, then RBAC: a same-tenant token without ai.query is
//     refused (403) on the API and the CLI, for RCA and the Explorer; one
//     with ai.query but only entities.read gets an answer whose metrics,
//     events and topology steps are blocked and hold no evidence; one
//     without test.read cannot read the path source. A subject naming the
//     other tenant's incident finds nothing; a subject naming a tenant is
//     refused (422).
//     6. The rendered Ask and Explore pages show each tenant its own answer and
//     rows, and nothing of the other's.
//     7. No egress: the recording proxy saw no request at all, and the control
//     plane logged no remote egress. The control plane is then redeployed
//     with a REMOTE model adapter (an OpenAI-compatible endpoint behind
//     PROBECTL_AI_EGRESS_ACK): a tenant that never consented is refused
//     (403), the refusal is in its audit chain, and still nothing reaches
//     the proxy.
func TestAIRootCauseRealStack(t *testing.T) {
	python := analyzerPython(t)
	proxy := startEgressRecorder(t)
	st := shipped.Start(t, shipped.Options{Name: "airca", TenantBand: 4, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "testsync-signing-key.pem"),
		"PROBECTL_ALERT_EVAL_INTERVAL":       evalInterval.String(),
		"HTTPS_PROXY":                        proxy.url(),
		"HTTP_PROXY":                         proxy.url(),
		"NO_PROXY":                           "127.0.0.1",
	}})
	op := st.OnboardOperator(t, "root@msp-airca.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)

	A := &rcaTenant{slug: "rca-acme-" + run, name: "RCA Acme", model: "pooled", admin: "ada@acme.example",
		prefix: prefixA, question: "Why is the service at " + serviceHost + " failing?"}
	B := &rcaTenant{slug: "rca-globex-" + run, name: "RCA Globex", model: "hybrid", admin: "bob@globex.example",
		prefix: prefixB, question: fmt.Sprintf("Why is %s routing through AS%d?", prefixB, noTransitB)}
	tenants := []*rcaTenant{A, B}

	// 1. Tenants, agents, tests and rules.
	for i, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark = row.ID, fmt.Sprintf("rca%d-%s", i, run)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = tn.mintToken(t, st, "receipt-cli", "tenant.read", "ai.query", "metrics.read", "events.read",
			"entities.read", "topology.read", "incident.read", "test.read", "test.write", "test.allow_private",
			"agent.write", "alert.read", "alert.write")
		tn.service = newFlapTarget(t)
		tn.agentID = uuid.NewString()
		tn.agentName = "rca-agent-" + tn.id[:8]
		identity := st.EnrollAgent(t, tn.id, tn.agentID, tn.agentName)
		st.StartAgent(t, identity, tn.agentName, []string{"tcp"}, `test_sync:
  enabled: true
  interval: 2s
  allowed_types: [tcp]
  allow_private_targets: true
`)
	}
	for _, tn := range tenants {
		tn.createTest(t, st)
		tn.createRule(t, st)
	}
	for _, tn := range tenants {
		shipped.Await(t, probeMetric+" = 1 for "+tn.slug+"'s service", 120*time.Second, func() bool {
			v, ok := promValue(t, fmt.Sprintf(`max(%s{tenant_id=%q,test_id=%q})`, probeMetric, tn.id, tn.testID))
			return ok && v == 1
		})
	}
	A.setupBGPAPI(t, st)
	B.setupBGPCLI(t, st)
	A.tracePath(t, st)

	// 2. The faults. A: the hijack first, then the outage it causes.
	A.watch = map[string]any{"prefix": prefixA, "expected_origins": []int{originA}}
	A.runAnalyzer(t, st, python, writeMRT(t, prefixA, []uint32{upstreamASN, originA}, []uint32{upstreamASN, hijackerA}))
	A.awaitIncident(t, st, "A's hijack", []string{"bgp.possible_hijack", "bgp.origin_change"})
	A.service.down(t)
	A.awaitIncident(t, st, "A's outage alert joining the hijack", []string{"bgp.possible_hijack", "bgp.origin_change", "alert.firing"})
	// B: a leak, and B's service stays up.
	B.watch = map[string]any{"prefix": prefixB, "expected_origins": []int{originB}, "no_transit": []int{noTransitB}}
	B.runAnalyzer(t, st, python, writeMRT(t, prefixB, []uint32{upstreamASN, originB}, []uint32{upstreamASN, noTransitB, originB}))
	B.awaitIncident(t, st, "B's leak", []string{"bgp.possible_leak"})
	for _, tn := range tenants {
		tn.checkIncidents(t, st)
	}
	checkIncidentRLS(t, st, tenants)
	if v, ok := promValue(t, fmt.Sprintf(`max(%s{tenant_id=%q,test_id=%q})`, probeMetric, B.id, B.testID)); !ok || v != 1 {
		t.Errorf("B's service probe reads %v (ok=%v) after the faults, want 1: B's fault is routing only", v, ok)
	}

	// 3. Root-cause analysis through the API and the CLI.
	for _, tn := range tenants {
		api := tn.askAPI(t, st)
		cli := tn.askCLI(t, st)
		for surface, ans := range map[string]*rcaAnswer{"POST /v1/ai/ask": api, "probectl ai ask": cli} {
			tn.checkAnswer(t, st, surface, ans)
		}
	}
	for _, tn := range tenants {
		tn.checkNothingOf(t, tn.other(A, B))
	}

	// 4. The Explorer.
	for _, tn := range tenants {
		tn.checkExplorer(t, st, tn.other(A, B))
	}

	// 5. Tenant first, then RBAC.
	A.checkRBAC(t, st, B)

	// 6. The rendered Ask and Explore pages.
	for _, tn := range tenants {
		tn.renderAsk(t, st, tn.other(A, B))
		tn.renderExplore(t, st, tn.other(A, B))
	}
	for _, tn := range tenants {
		tn.checkNothingOf(t, tn.other(A, B))
	}

	// 7. No egress, then a remote adapter without consent.
	checkNoEgress(t, st, proxy)
	checkRemoteAdapterNeedsConsent(t, st, proxy, tenants)
}

// --- the tenants ---

type rcaTenant struct {
	slug, name, model, admin string
	prefix, question, mark   string
	id, cookie, token        string
	service                  *flapTarget
	agentID, agentName       string
	testID, testName         string
	ruleID, ruleName         string
	bgpSource, lane          string
	watch                    map[string]any
	pathTarget               string
	incidentID               string
	seen                     [][]byte // every answer, explorer result and rendered page, for the byte search
	mu                       sync.Mutex
}

func (tn *rcaTenant) other(a, b *rcaTenant) *rcaTenant {
	if tn == a {
		return b
	}
	return a
}

func (tn *rcaTenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

func (tn *rcaTenant) keep(raw []byte) {
	tn.mu.Lock()
	tn.seen = append(tn.seen, append([]byte(nil), raw...))
	tn.mu.Unlock()
}

// identifiers are the strings that are this tenant's alone: anything another
// tenant is shown that holds one of them crossed the tenant boundary.
func (tn *rcaTenant) identifiers() []string {
	out := []string{tn.id, tn.slug, tn.mark, tn.testID, tn.agentID, tn.ruleID, tn.incidentID, tn.bgpSource}
	if tn.prefix == prefixA {
		out = append(out, prefixA, "AS"+strconv.Itoa(hijackerA), "AS"+strconv.Itoa(originA), "as:"+strconv.Itoa(hijackerA))
	} else {
		out = append(out, prefixB, "AS"+strconv.Itoa(noTransitB), "["+strconv.Itoa(noTransitB)+"]", "as:"+strconv.Itoa(originB))
	}
	return slices.DeleteFunc(out, func(s string) bool { return s == "" })
}

func (tn *rcaTenant) do(t *testing.T, st *shipped.Stack, method, route string, body, out any, want int) []byte {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, method, route, body)
	if code != want || (out != nil && json.Unmarshal(raw, out) != nil) {
		t.Fatalf("%s %s as %s = %d (want %d): %.500s", method, route, tn.slug, code, want, raw)
	}
	return raw
}

// bearer sends a request with an API token, as a script or integration does.
func bearer(t *testing.T, st *shipped.Stack, token, method, route string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, st.BaseURL+route, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := st.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, route, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, out
}

// mintToken mints, from the admin's browser session, an API token holding
// exactly scopes.
func (tn *rcaTenant) mintToken(t *testing.T, st *shipped.Stack, name string, scopes ...string) string {
	t.Helper()
	var out struct{ Token string }
	tn.do(t, st, http.MethodPost, "/v1/api-tokens", map[string]any{"name": name, "scopes": scopes}, &out, http.StatusCreated)
	if out.Token == "" {
		t.Fatalf("POST /v1/api-tokens (%s) as %s returned no token", name, tn.slug)
	}
	return out.Token
}

func (tn *rcaTenant) createTest(t *testing.T, st *shipped.Stack) {
	t.Helper()
	tn.testName = "tcp service " + tn.mark
	var test struct{ ID string }
	tn.do(t, st, http.MethodPost, "/v1/tests", map[string]any{
		"name": tn.testName, "type": "tcp", "target": tn.service.addr, "interval_seconds": 10,
		"timeout_seconds": 3, "enabled": true, "params": map[string]string{"allow_private_targets": "true"},
	}, &test, http.StatusCreated)
	tn.testID = test.ID
}

// createRule watches every probe of the tenant's (no label match): only the
// tenant pin keeps the other tenant's probes on the same address out.
func (tn *rcaTenant) createRule(t *testing.T, st *shipped.Stack) {
	t.Helper()
	tn.ruleName = "service down " + tn.mark
	var rule struct{ ID string }
	tn.do(t, st, http.MethodPost, "/v1/alerts", map[string]any{
		"name": tn.ruleName, "metric": probeMetric, "type": "threshold", "comparison": "lt", "threshold": 1,
		"for_n": 1, "renotify_seconds": 0, "severity": "critical",
	}, &rule, http.StatusCreated)
	tn.ruleID = rule.ID
}

// tracePath discovers the path to the tenant's service from the control
// plane (F3), a round in ClickHouse's path tables.
func (tn *rcaTenant) tracePath(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var p struct {
		Target             string `json:"target"`
		DestinationReached bool   `json:"destination_reached"`
	}
	tn.do(t, st, http.MethodPost, "/v1/tests/"+tn.testID+"/path", nil, &p, http.StatusOK)
	if p.Target == "" || !p.DestinationReached {
		t.Fatalf("POST /v1/tests/%s/path as %s = %+v, want a traced path that reached the service", tn.testID, tn.slug, p)
	}
	tn.pathTarget = p.Target
	t.Logf("%s traced its service from the control plane (path target %s)", tn.slug, tn.pathTarget)
}

// --- the BGP plane ---

type registration struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	Plane    string `json:"plane"`
	Config   struct {
		Env map[string]string `json:"env"`
	} `json:"config"`
}

func (tn *rcaTenant) bindSource(t *testing.T, surface string, reg registration) {
	t.Helper()
	env := reg.Config.Env
	if reg.TenantID != tn.id || reg.Plane != "bgp" || reg.AgentID == "" || env["PROBECTL_BMP_TENANT_ID"] != tn.id ||
		env["PROBECTL_BMP_BUS_NAMESPACE"] == "" {
		t.Fatalf("%s as %s returned %+v, want a bgp source bound to the tenant with its lane", surface, tn.slug, reg)
	}
	tn.bgpSource, tn.lane = reg.AgentID, env["PROBECTL_BMP_BUS_NAMESPACE"]
	t.Logf("%s registered BGP source %s on lane %s (%s)", tn.slug, tn.bgpSource, tn.lane, surface)
}

func (tn *rcaTenant) setupBGPAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var tok struct{ Token string }
	tn.do(t, st, http.MethodPost, "/v1/agents/enroll-tokens", map[string]any{"name": labCollector, "ttl_seconds": 600}, &tok, http.StatusCreated)
	var reg registration
	tn.do(t, st, http.MethodPost, "/v1/collectors/register",
		map[string]any{"token": tok.Token, "plane": "bgp", "hostname": labCollector}, &reg, http.StatusCreated)
	tn.bindSource(t, "POST /v1/collectors/register", reg)
}

func (tn *rcaTenant) setupBGPCLI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var tok struct{ Token string }
	st.MustCLI(t, tn.env(), &tok, "agent", "enroll-token", "--body", fmt.Sprintf(`{"name":%q,"ttl_seconds":600}`, labCollector))
	var reg registration
	st.MustCLI(t, tn.env(), &reg, "bgp", "setup", "--body-file", st.SecretFile(t,
		map[string]any{"token": tok.Token, "plane": "bgp", "hostname": labCollector}))
	tn.bindSource(t, "probectl bgp setup", reg)
}

// runAnalyzer runs the tenant's shipped analyzer sidecar once over the MRT
// with the tenant's own watch config (a finite source: it publishes, exits).
func (tn *rcaTenant) runAnalyzer(t *testing.T, st *shipped.Stack, python, mrt string) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "analyzer.json")
	writeJSONFile(t, cfg, map[string]any{"tenant_id": tn.id, "collector": labCollector, "monitored_prefixes": []map[string]any{tn.watch}})
	cmd := exec.Command(st.Control, "bgp-analyzer")
	cmd.Dir = st.Dir
	cmd.Env = append(os.Environ(),
		"PROBECTL_BGP_ANALYZER_CONFIG="+cfg,
		"PROBECTL_BGP_ANALYZER_SOURCE=mrt",
		"PROBECTL_BGP_ANALYZER_SOURCE_FILE="+mrt,
		"PROBECTL_BGP_ANALYZER_BUS_NAMESPACE="+tn.lane,
		"PROBECTL_BGP_ANALYZER_PYTHON="+python,
		"PYTHONPATH="+filepath.Join(st.Root, "analyzer"),
		"PROBECTL_BUS_MODE=kafka",
		"PROBECTL_BUS_BROKERS="+strings.Join(testsupport.KafkaBrokers(), ","),
		"PROBECTL_BUS_ALLOW_PLAINTEXT=true", // the dev stack's Kafka is plaintext
	)
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(st.Dir, "bgp-analyzer-"+tn.slug+".log"), out, 0o600)
	if err != nil || !strings.Contains(string(out), `"bgp analyzer completed"`) {
		t.Fatalf("probectl-control bgp-analyzer (mrt) for %s: %v\n%s", tn.slug, err, out)
	}
	t.Logf("%s's analyzer sidecar read the lab collector's MRT with its watch config %v", tn.slug, tn.watch)
}

// writeMRT encodes the lab collector's MRT (RFC 6396): a TABLE_DUMP_V2 RIB
// holding the baseline route, then one BGP4MP_MESSAGE_AS4 UPDATE announcing
// the changed path, both stamped now.
func writeMRT(t *testing.T, prefix string, baseline, changed []uint32) string {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	ts := uint32(time.Now().Unix()) //nolint:gosec // seconds since 1970 fit uint32 until 2106
	var raw []byte
	raw = append(raw, mrtPeerIndexTable(ts)...)
	raw = append(raw, mrtRIBIPv4(ts, p, baseline)...)
	raw = append(raw, mrtUpdateAS4(ts+1, p, changed)...)
	path := filepath.Join(t.TempDir(), "updates.mrt")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mrtRecord(ts uint32, typ, subtype uint16, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, ts)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, subtype)
	b = binary.BigEndian.AppendUint32(b, uint32(len(body))) //nolint:gosec // a few dozen bytes
	return append(b, body...)
}

func mrtASPath(asns []uint32) []byte {
	seg := []byte{2, byte(len(asns))} // AS_SEQUENCE
	for _, a := range asns {
		seg = binary.BigEndian.AppendUint32(seg, a)
	}
	return append([]byte{0x40, 2, byte(len(seg))}, seg...) // well-known transitive AS_PATH
}

func mrtNLRI(p netip.Prefix) []byte {
	a := p.Addr().As4()
	return append([]byte{byte(p.Bits())}, a[:(p.Bits()+7)/8]...)
}

var (
	mrtPeerIP  = netip.MustParseAddr("192.0.2.1").As4()
	mrtLocalIP = netip.MustParseAddr("192.0.2.2").As4()
)

func mrtPeerIndexTable(ts uint32) []byte {
	b := binary.BigEndian.AppendUint32(nil, 1)         // collector BGP id
	b = binary.BigEndian.AppendUint16(b, 0)            // empty view name
	b = binary.BigEndian.AppendUint16(b, 1)            // one peer
	b = append(b, 0x02)                                // IPv4 address, 4-byte ASN
	b = binary.BigEndian.AppendUint32(b, 0)            // peer BGP id
	b = append(b, mrtPeerIP[:]...)                     // peer address
	b = binary.BigEndian.AppendUint32(b, collectorASN) // peer AS
	return mrtRecord(ts, 13, 1, b)                     // TABLE_DUMP_V2 / PEER_INDEX_TABLE
}

func mrtRIBIPv4(ts uint32, p netip.Prefix, asns []uint32) []byte {
	attrs := mrtASPath(asns)
	b := binary.BigEndian.AppendUint32(nil, 0) // sequence
	b = append(b, mrtNLRI(p)...)
	b = binary.BigEndian.AppendUint16(b, 1)                  // one entry
	b = binary.BigEndian.AppendUint16(b, 0)                  // peer index
	b = binary.BigEndian.AppendUint32(b, ts)                 // originated
	b = binary.BigEndian.AppendUint16(b, uint16(len(attrs))) //nolint:gosec // one short attribute
	b = append(b, attrs...)
	return mrtRecord(ts, 13, 2, b) // TABLE_DUMP_V2 / RIB_IPV4_UNICAST
}

func mrtUpdateAS4(ts uint32, p netip.Prefix, asns []uint32) []byte {
	attrs := mrtASPath(asns)
	update := binary.BigEndian.AppendUint16(nil, 0)                    // no withdrawals
	update = binary.BigEndian.AppendUint16(update, uint16(len(attrs))) //nolint:gosec // one short attribute
	update = append(update, attrs...)
	update = append(update, mrtNLRI(p)...)
	msg := bytes.Repeat([]byte{0xff}, 16)
	msg = binary.BigEndian.AppendUint16(msg, uint16(19+len(update))) //nolint:gosec // one short UPDATE
	msg = append(msg, 2)                                             // UPDATE
	msg = append(msg, update...)
	b := binary.BigEndian.AppendUint32(nil, collectorASN) // peer AS
	b = binary.BigEndian.AppendUint32(b, 0)               // local AS
	b = binary.BigEndian.AppendUint16(b, 0)               // interface index
	b = binary.BigEndian.AppendUint16(b, 1)               // AFI IPv4
	b = append(b, mrtPeerIP[:]...)
	b = append(b, mrtLocalIP[:]...)
	b = append(b, msg...)
	return mrtRecord(ts, 16, 4, b) // BGP4MP / BGP4MP_MESSAGE_AS4
}

// --- incidents ---

type incidentSignal struct {
	ID         string            `json:"id"`
	Plane      string            `json:"plane"`
	Kind       string            `json:"kind"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Target     string            `json:"target"`
	Prefix     string            `json:"prefix"`
	Attributes map[string]string `json:"attributes"`
}

type incidentRecord struct {
	ID          string           `json:"id"`
	TenantID    string           `json:"tenant_id"`
	Status      string           `json:"status"`
	Title       string           `json:"title"`
	Target      string           `json:"target"`
	Prefix      string           `json:"prefix"`
	SignalCount int              `json:"signal_count"`
	Signals     []incidentSignal `json:"signals"`
}

func (tn *rcaTenant) incidents(t *testing.T, st *shipped.Stack) []incidentRecord {
	t.Helper()
	var list struct {
		Items []incidentRecord `json:"items"`
	}
	tn.do(t, st, http.MethodGet, "/v1/incidents", nil, &list, http.StatusOK)
	out := make([]incidentRecord, 0, len(list.Items))
	for _, inc := range list.Items {
		var full incidentRecord
		tn.do(t, st, http.MethodGet, "/v1/incidents/"+url.PathEscape(inc.ID), nil, &full, http.StatusOK)
		out = append(out, full)
	}
	return out
}

func kinds(inc incidentRecord) []string {
	out := make([]string, 0, len(inc.Signals))
	for _, s := range inc.Signals {
		out = append(out, s.Kind)
	}
	slices.Sort(out)
	return out
}

// awaitIncident waits until the tenant has exactly one incident holding
// exactly the signal kinds want.
func (tn *rcaTenant) awaitIncident(t *testing.T, st *shipped.Stack, what string, want []string) {
	t.Helper()
	want = slices.Sorted(slices.Values(want))
	deadline := time.Now().Add(120 * time.Second)
	for {
		incs := tn.incidents(t, st)
		if len(incs) == 1 && slices.Equal(kinds(incs[0]), want) {
			tn.incidentID = incs[0].ID
			t.Logf("%s: %s's incident %s holds %v", what, tn.slug, tn.incidentID, want)
			return
		}
		if time.Now().After(deadline) {
			var got [][]string
			for _, inc := range incs {
				got = append(got, kinds(inc))
			}
			t.Fatalf("%s: %s never had exactly one incident of %v; it has %d: %v", what, tn.slug, want, len(incs), got)
		}
		time.Sleep(time.Second)
	}
}

// checkIncidents: exactly one incident, the tenant's own, of the planes its
// fault touched, every signal of it the tenant's.
func (tn *rcaTenant) checkIncidents(t *testing.T, st *shipped.Stack) {
	t.Helper()
	incs := tn.incidents(t, st)
	if len(incs) != 1 {
		t.Fatalf("%s has %d incidents, want exactly the one its fault opened", tn.slug, len(incs))
	}
	inc := incs[0]
	planes := map[string]bool{}
	for _, s := range inc.Signals {
		planes[s.Plane] = true
	}
	wantPlanes := map[string]bool{"bgp": true}
	if tn.prefix == prefixA {
		wantPlanes["network"] = true
	}
	if inc.TenantID != tn.id || inc.Status != "open" || len(planes) != len(wantPlanes) {
		t.Errorf("%s's incident = %+v (planes %v), want one open incident of the tenant over %v", tn.slug, inc, planes, wantPlanes)
	}
	for p := range wantPlanes {
		if !planes[p] {
			t.Errorf("%s's incident has no %s signal: %v", tn.slug, p, kinds(inc))
		}
	}
	for _, s := range inc.Signals {
		if s.Plane == "bgp" && s.Prefix != tn.prefix {
			t.Errorf("%s's incident holds a BGP signal for %s, not its own %s", tn.slug, s.Prefix, tn.prefix)
		}
		if s.Plane == "network" && s.Target != serviceHost {
			t.Errorf("%s's incident holds an alert on %q, want its service %s", tn.slug, s.Target, serviceHost)
		}
	}
	t.Logf("%s: one incident %s (%q) over %d planes: %v", tn.slug, inc.ID, inc.Title, len(planes), kinds(inc))
}

// checkIncidentRLS counts the incidents table as the app role every tenant
// read runs as, scoped to a tenant by the per-transaction setting and with NO
// tenant_id predicate: PostgreSQL row security, not the query, isolates.
func checkIncidentRLS(t *testing.T, st *shipped.Stack, tenants []*rcaTenant) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var total int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM incidents`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	for _, tn := range tenants {
		var own int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE tenant_id = $1`, tn.id).Scan(&own); err != nil {
			t.Fatal(err)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var seen int
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, tn.id); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM incidents`).Scan(&seen); err != nil {
			t.Fatal(err)
		}
		_ = tx.Rollback(ctx)
		if own != 1 || seen != own || own >= total {
			t.Errorf("as the app role scoped to %s, a predicate-free count of incidents saw %d; the tenant owns %d of %d: the storage layer is not enforcing tenant isolation",
				tn.slug, seen, own, total)
		}
	}
}

// --- root-cause analysis ---

type citation struct {
	EvidenceID string `json:"evidence_id"`
}

type rcaEvidence struct {
	ID       string         `json:"id"`
	Domain   string         `json:"domain"`
	Plane    string         `json:"plane"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Summary  string         `json:"summary"`
	Ref      string         `json:"ref"`
	Fields   map[string]any `json:"fields"`
}

type rcaAnswer struct {
	ID                 string     `json:"id"`
	Tenant             string     `json:"tenant"`
	RootCause          string     `json:"root_cause"`
	RootCauseCitations []citation `json:"root_cause_citations"`
	RootCauseGrounded  bool       `json:"root_cause_grounded"`
	Confidence         string     `json:"confidence"`
	InvestigationPlan  []struct {
		Domain        string `json:"domain"`
		Status        string `json:"status"`
		EvidenceCount int    `json:"evidence_count"`
		Reason        string `json:"reason"`
	} `json:"investigation_plan"`
	Findings []struct {
		Statement string     `json:"statement"`
		Citations []citation `json:"citations"`
	} `json:"findings"`
	Evidence  []rcaEvidence `json:"evidence"`
	Model     string        `json:"model"`
	Reasoning struct {
		Adapter       string `json:"adapter"`
		Execution     string `json:"execution"`
		EgressConsent string `json:"egress_consent"`
	} `json:"reasoning"`
	InsufficientEvidence bool `json:"insufficient_evidence"`
	Degraded             bool `json:"degraded"`
}

func decodeAnswer(t *testing.T, surface string, raw []byte) *rcaAnswer {
	t.Helper()
	var ans rcaAnswer
	if err := json.Unmarshal(raw, &ans); err != nil {
		t.Fatalf("%s: decode the answer: %v: %.300s", surface, err, raw)
	}
	return &ans
}

func (tn *rcaTenant) askAPI(t *testing.T, st *shipped.Stack) *rcaAnswer {
	t.Helper()
	raw := tn.do(t, st, http.MethodPost, "/v1/ai/ask", map[string]any{"question": tn.question}, nil, http.StatusOK)
	tn.keep(raw)
	return decodeAnswer(t, "POST /v1/ai/ask as "+tn.slug, raw)
}

func (tn *rcaTenant) askCLI(t *testing.T, st *shipped.Stack) *rcaAnswer {
	t.Helper()
	body, err := json.Marshal(map[string]any{"question": tn.question})
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := st.CLI(tn.env(), "ai", "ask", "--body", string(body))
	tn.keep([]byte(stdout + stderr))
	if code != 0 {
		t.Fatalf("probectl ai ask as %s: exit %d: %s%s", tn.slug, code, stderr, stdout)
	}
	return decodeAnswer(t, "probectl ai ask as "+tn.slug, []byte(stdout))
}

// checkAnswer: the answer is the builtin adapter's, its root cause is
// grounded in the injected fault, and every citation resolves to a real
// record in the tenant's own stores.
func (tn *rcaTenant) checkAnswer(t *testing.T, st *shipped.Stack, surface string, ans *rcaAnswer) {
	t.Helper()
	if ans.Tenant != tn.id || ans.Model != "builtin" || ans.Reasoning.Adapter != "builtin" ||
		ans.Reasoning.Execution != "builtin_local" || ans.Reasoning.EgressConsent != "not_required" || ans.Degraded {
		t.Errorf("%s as %s: tenant %q model %q reasoning %+v degraded %v, want the tenant's answer from the builtin adapter, local, no consent needed",
			surface, tn.slug, ans.Tenant, ans.Model, ans.Reasoning, ans.Degraded)
	}
	if !ans.RootCauseGrounded || ans.InsufficientEvidence || len(ans.RootCauseCitations) == 0 {
		t.Fatalf("%s as %s: root cause %q grounded=%v insufficient=%v citations=%v, want a grounded, cited root cause",
			surface, tn.slug, ans.RootCause, ans.RootCauseGrounded, ans.InsufficientEvidence, ans.RootCauseCitations)
	}
	byID := map[string]rcaEvidence{}
	for _, e := range ans.Evidence {
		byID[e.ID] = e
	}
	cites := append([]citation(nil), ans.RootCauseCitations...)
	for _, f := range ans.Findings {
		if len(f.Citations) == 0 {
			t.Errorf("%s as %s: finding %q cites nothing", surface, tn.slug, f.Statement)
		}
		cites = append(cites, f.Citations...)
	}
	for _, c := range cites {
		if _, ok := byID[c.EvidenceID]; !ok {
			t.Errorf("%s as %s: a citation names evidence %q the answer does not hold: a fabricated citation passed", surface, tn.slug, c.EvidenceID)
		}
	}

	stores := tn.loadStores(t, st)
	domains := map[string]int{}
	planes := map[string]bool{}
	for _, e := range ans.Evidence {
		if err := stores.resolve(t, e); err != nil {
			t.Errorf("%s as %s: evidence %s (%s/%s %q) does not resolve to a record of the tenant's: %v", surface, tn.slug, e.ID, e.Domain, e.Plane, e.Title, err)
			continue
		}
		domains[e.Domain]++
		planes[e.Plane] = true
	}

	// The root cause names the injected fault, through the signal it cites.
	primary, ok := byID[ans.RootCauseCitations[0].EvidenceID]
	wantKind, wantTerms := "bgp.possible_leak", []string{prefixB, strconv.Itoa(noTransitB)}
	if tn.prefix == prefixA {
		wantKind, wantTerms = "bgp.possible_hijack", []string{prefixA, "AS" + strconv.Itoa(hijackerA)}
	}
	if !ok || primary.Domain != "entities" || primary.Plane != "bgp" || primary.Fields["kind"] != wantKind {
		t.Errorf("%s as %s: the root cause cites %+v, want the %s signal of the tenant's incident", surface, tn.slug, primary, wantKind)
	}
	for _, term := range wantTerms {
		if !strings.Contains(ans.RootCause, term) || !strings.Contains(primary.Title, term) {
			t.Errorf("%s as %s: root cause %q (cited %q) does not name %s of the injected fault", surface, tn.slug, ans.RootCause, primary.Title, term)
		}
	}
	tn.checkBGPEvent(t, st, surface, primary, wantKind)

	// Every plane the fault touched spoke, and only the tenant's stores did.
	wantDomains := map[string]int{"entities": 2}
	wantPlanes := []string{"incident", "bgp"}
	if tn.prefix == prefixA {
		wantDomains = map[string]int{"entities": 4, "metrics": 1}
		wantPlanes = append(wantPlanes, "network", "metrics")
	} else {
		wantDomains["topology"] = 1
		wantPlanes = append(wantPlanes, "topology")
	}
	for d, n := range wantDomains {
		if domains[d] < n {
			t.Errorf("%s as %s: %d resolved %s evidence items, want at least %d (all: %v)", surface, tn.slug, domains[d], d, n, domains)
		}
	}
	for _, p := range wantPlanes {
		if !planes[p] {
			t.Errorf("%s as %s: no evidence from the %s plane (planes: %v)", surface, tn.slug, p, planes)
		}
	}
	for _, step := range ans.InvestigationPlan {
		if step.Status != "queried" {
			t.Errorf("%s as %s: investigation step %s is %s (%s), want queried with full read scopes", surface, tn.slug, step.Domain, step.Status, step.Reason)
		}
	}
	t.Logf("%s as %s: %q [%s confidence] citing %s = %s signal %v of incident %s; %d evidence items resolved (%v) over planes %v",
		surface, tn.slug, ans.RootCause, ans.Confidence, primary.ID, primary.Fields["kind"], primary.Fields["id"], tn.incidentID, len(ans.Evidence), domains, keys(planes))
}

// checkBGPEvent follows the root cause's signal to the BGP event read model:
// the tenant's GET /v1/bgp/events lists that event, on the tenant's incident.
func (tn *rcaTenant) checkBGPEvent(t *testing.T, st *shipped.Stack, surface string, primary rcaEvidence, kind string) {
	t.Helper()
	var out struct {
		Items []struct {
			ID         string            `json:"id"`
			IncidentID string            `json:"incident_id"`
			Kind       string            `json:"kind"`
			Title      string            `json:"title"`
			Prefix     string            `json:"prefix"`
			Attributes map[string]string `json:"attributes"`
		} `json:"items"`
	}
	tn.do(t, st, http.MethodGet, "/v1/bgp/events?limit=200", nil, &out, http.StatusOK)
	wantOrigin := strconv.Itoa(originB)
	if tn.prefix == prefixA {
		wantOrigin = strconv.Itoa(hijackerA)
	}
	for _, e := range out.Items {
		if e.Kind == kind && e.Title == primary.Title && e.IncidentID == tn.incidentID && e.Prefix == tn.prefix &&
			e.Attributes["new_origin_asn"] == wantOrigin && e.Attributes["collector"] == labCollector {
			return
		}
	}
	t.Errorf("%s as %s: GET /v1/bgp/events lists no %s event %q on incident %s for %s from %s (origin AS%s): %+v",
		surface, tn.slug, kind, primary.Title, tn.incidentID, tn.prefix, labCollector, wantOrigin, out.Items)
}

// tenantStores is what the tenant's own stores hold, read through the public
// API and straight from Prometheus, to resolve each evidence item against.
type tenantStores struct {
	tn        *rcaTenant
	incidents map[string]incidentRecord
	nodes     map[string]bool
}

func (tn *rcaTenant) loadStores(t *testing.T, st *shipped.Stack) *tenantStores {
	t.Helper()
	s := &tenantStores{tn: tn, incidents: map[string]incidentRecord{}, nodes: map[string]bool{}}
	for _, inc := range tn.incidents(t, st) {
		s.incidents[inc.ID] = inc
	}
	var topo struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
	}
	tn.do(t, st, http.MethodGet, "/v1/topology", nil, &topo, http.StatusOK)
	for _, n := range topo.Nodes {
		s.nodes[n.ID] = true
	}
	return s
}

func field(e rcaEvidence, key string) string {
	v, _ := e.Fields[key].(string)
	return v
}

// resolve follows one evidence item to the record it names.
func (s *tenantStores) resolve(t *testing.T, e rcaEvidence) error {
	t.Helper()
	switch e.Domain {
	case "entities":
		id := field(e, "id")
		if field(e, "kind") == "incident" {
			inc, ok := s.incidents[id]
			if !ok || inc.Title != e.Title {
				return fmt.Errorf("incident %q is not one of the tenant's (%v)", id, keys(s.incidents))
			}
			return nil
		}
		// A signal is cited by its stored id (<incident>:<signal id>), never by
		// its place in the timeline.
		incID, sigID, ok := strings.Cut(id, ":")
		inc, found := s.incidents[incID]
		j := slices.IndexFunc(inc.Signals, func(sig incidentSignal) bool { return sig.ID == sigID })
		if !ok || !found || sigID == "" || j < 0 || field(e, "signal_id") != sigID || field(e, "incident_id") != incID {
			return fmt.Errorf("signal %q names no stored signal of the tenant's incidents", id)
		}
		sig := inc.Signals[j]
		if sig.Kind != field(e, "kind") || sig.Title != e.Title || sig.Plane != e.Plane {
			return fmt.Errorf("signal %q is %s %q on the %s plane in the incident, but the evidence says %s %q on %s",
				id, sig.Kind, sig.Title, sig.Plane, field(e, "kind"), e.Title, e.Plane)
		}
		return nil
	case "metrics":
		metric, agent, target := field(e, "metric"), field(e, "agent_id"), field(e, "target")
		if agent != s.tn.agentID || target == "" || !strings.HasPrefix(metric, "probectl_") {
			return fmt.Errorf("series %s{agent_id=%q, target=%q} is not a series of the tenant's agent %s", metric, agent, target, s.tn.agentID)
		}
		q := fmt.Sprintf(`%s{tenant_id=%q,agent_id=%q,server_address=%q}`, metric, s.tn.id, agent, target)
		v, ok := promValue(t, q)
		if !ok {
			return fmt.Errorf("prometheus holds no series %s", q)
		}
		if metric == probeMetric {
			cited, _ := e.Fields["value"].(float64)
			if cited != v {
				return fmt.Errorf("the evidence says %s = %v, prometheus says %v", q, cited, v)
			}
		}
		return nil
	case "topology":
		node := field(e, "node")
		if !s.nodes[node] {
			return fmt.Errorf("node %q is not in the tenant's topology", node)
		}
		if n := field(e, "neighbor"); n != "" && !s.nodes[n] {
			return fmt.Errorf("neighbor %q is not in the tenant's topology", n)
		}
		return nil
	default:
		return fmt.Errorf("no record of the %s domain is expected for this fault", e.Domain)
	}
}

// checkNothingOf byte-searches everything this tenant was shown for the
// other tenant's identifiers, prefixes and ASNs.
func (tn *rcaTenant) checkNothingOf(t *testing.T, other *rcaTenant) {
	t.Helper()
	tn.mu.Lock()
	defer tn.mu.Unlock()
	if len(tn.seen) == 0 {
		t.Fatalf("nothing was shown to %s to search", tn.slug)
	}
	for i, raw := range tn.seen {
		for _, id := range other.identifiers() {
			if bytes.Contains(raw, []byte(id)) {
				t.Errorf("response/page %d shown to %s holds %q of %s's: %.400s", i, tn.slug, id, other.slug, raw)
			}
		}
	}
}

// --- the Explorer ---

type explorerResult struct {
	Rows      []map[string]any `json:"rows"`
	Execution struct {
		Source       string `json:"source"`
		TenantScoped bool   `json:"tenant_scoped"`
		ReturnedRows int    `json:"returned_rows"`
	} `json:"execution"`
}

func pathQuery(target string) map[string]any {
	return map[string]any{
		"template": "loss-by-hop", "question": "Show loss by hop for this test", "source": "path",
		"dimensions": []string{"target", "hop", "node"}, "groupings": []string{"hop"},
		"measures": []string{"loss_ratio", "rtt_avg_ms"}, "visualization": "line",
		"filters": map[string]string{"target": target},
	}
}

func topologyQuery() map[string]any {
	return map[string]any{
		"template": "service-dependencies", "question": "Show service dependencies", "source": "topology",
		"dimensions": []string{"from", "to", "kind"}, "groupings": []string{"kind"},
		"measures": []string{"edges"}, "visualization": "topology",
	}
}

func (tn *rcaTenant) exploreAPI(t *testing.T, st *shipped.Stack, q map[string]any) explorerResult {
	t.Helper()
	var out explorerResult
	tn.keep(tn.do(t, st, http.MethodPost, "/v1/explorer/query", q, &out, http.StatusOK))
	return out
}

func (tn *rcaTenant) exploreCLI(t *testing.T, st *shipped.Stack, q map[string]any) explorerResult {
	t.Helper()
	var out explorerResult
	stdout, stderr, code := st.CLI(tn.env(), "explorer", "query", "--body-file", st.SecretFile(t, q))
	tn.keep([]byte(stdout + stderr))
	if code != 0 || json.Unmarshal([]byte(stdout), &out) != nil {
		t.Fatalf("probectl explorer query as %s: exit %d: %s%s", tn.slug, code, stderr, stdout)
	}
	return out
}

// awaitRoutingEdge polls the tenant's own Explorer until its routing edge is in
// its graph, failing after a minute. It only waits; checkExplorer asserts.
func (tn *rcaTenant) awaitRoutingEdge(t *testing.T, st *shipped.Stack, from, to string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, r := range tn.exploreAPI(t, st, topologyQuery()).Rows {
			if r["from"] == from && r["to"] == to && r["kind"] == "routing" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s's routing edge %s -> %s never reached its topology graph", tn.slug, from, to)
		}
		time.Sleep(time.Second)
	}
}

// routingEdge is the tenant's routing edge in its topology: its block,
// originated by the AS its fault left in place.
func (tn *rcaTenant) routingEdge() (from, to string) {
	if tn.prefix == prefixA {
		return "as:" + strconv.Itoa(hijackerA), "prefix:" + prefixA
	}
	return "as:" + strconv.Itoa(originB), "prefix:" + prefixB
}

func (tn *rcaTenant) checkExplorer(t *testing.T, st *shipped.Stack, other *rcaTenant) {
	t.Helper()
	target := tracer(tn, other).pathTarget
	for surface, res := range map[string]explorerResult{
		"POST /v1/explorer/query (path)": tn.exploreAPI(t, st, pathQuery(target)),
		"probectl explorer query (path)": tn.exploreCLI(t, st, pathQuery(target)),
	} {
		if res.Execution.Source != "path" || !res.Execution.TenantScoped {
			t.Errorf("%s as %s: execution %+v, want a tenant-scoped path read", surface, tn.slug, res.Execution)
		}
		if tn.pathTarget == "" {
			// B traced nothing: A's round on the same target must not answer.
			if len(res.Rows) != 0 {
				t.Errorf("%s as %s, which traced nothing, lists %v: another tenant's path round", surface, tn.slug, res.Rows)
			}
			continue
		}
		if len(res.Rows) == 0 {
			t.Errorf("%s as %s lists no hop of the round it traced", surface, tn.slug)
		}
		for _, r := range res.Rows {
			if r["target"] != tn.pathTarget || r["node"] != serviceHost {
				t.Errorf("%s as %s lists %v, want hops of its own round to %s", surface, tn.slug, r, tn.pathTarget)
			}
		}
	}
	from, to := tn.routingEdge()
	// The topology graph is fed by its own bus consumer, separate from the one
	// that opens incidents, so a tenant's routing edge can land shortly after
	// its incident does (CI run 39867660346 queried in that gap). Wait for the
	// edge to reach this tenant's own graph, then assert every surface once.
	tn.awaitRoutingEdge(t, st, from, to)
	for surface, res := range map[string]explorerResult{
		"POST /v1/explorer/query (topology)": tn.exploreAPI(t, st, topologyQuery()),
		"probectl explorer query (topology)": tn.exploreCLI(t, st, topologyQuery()),
	} {
		found := false
		for _, r := range res.Rows {
			if r["from"] == from && r["to"] == to && r["kind"] == "routing" {
				found = true
			}
		}
		if !found || res.Execution.Source != "topology" || !res.Execution.TenantScoped {
			t.Errorf("%s as %s = %v (%+v), want its own routing edge %s -> %s", surface, tn.slug, res.Rows, res.Execution, from, to)
		}
	}
	t.Logf("%s's Explorer: its path round (%q) and routing edge %s -> %s, through the API and the CLI", tn.slug, tn.pathTarget, from, to)
}

// tracer returns whichever of the two tenants traced a path.
func tracer(a, b *rcaTenant) *rcaTenant {
	if a.pathTarget != "" {
		return a
	}
	return b
}

// --- tenant first, then RBAC ---

func (tn *rcaTenant) checkRBAC(t *testing.T, st *shipped.Stack, other *rcaTenant) {
	t.Helper()
	ask := map[string]any{"question": tn.question}

	// No ai.query: every read scope the evidence needs, but not the assistant.
	noAI := tn.mintToken(t, st, "receipt-no-ai", "tenant.read", "metrics.read", "events.read", "entities.read",
		"topology.read", "incident.read", "test.read")
	if code, raw := bearer(t, st, noAI, http.MethodPost, "/v1/ai/ask", ask); code != http.StatusForbidden {
		t.Errorf("POST /v1/ai/ask with a %s token lacking ai.query = %d, want 403: %.300s", tn.slug, code, raw)
	}
	if code, raw := bearer(t, st, noAI, http.MethodPost, "/v1/explorer/query", topologyQuery()); code != http.StatusForbidden {
		t.Errorf("POST /v1/explorer/query with a %s token lacking ai.query = %d, want 403: %.300s", tn.slug, code, raw)
	}
	body, _ := json.Marshal(ask)
	out, errOut, code := st.CLI(map[string]string{"PROBECTL_API_TOKEN": noAI}, "ai", "ask", "--body", string(body))
	said := strings.ToLower(out + errOut)
	refused := strings.Contains(said, "403") || strings.Contains(said, "forbidden")
	if code == 0 || !refused {
		t.Errorf("probectl ai ask with a %s token lacking ai.query = exit %d: %.300s%.300s, want the 403 refusal", tn.slug, code, errOut, out)
	}

	// ai.query with only entities.read: the answer holds the incident and no
	// other domain's evidence; each other step says it was blocked.
	entitiesOnly := tn.mintToken(t, st, "receipt-entities-only", "tenant.read", "ai.query", "entities.read")
	code, raw := bearer(t, st, entitiesOnly, http.MethodPost, "/v1/ai/ask", ask)
	tn.keep(raw)
	if code != http.StatusOK {
		t.Fatalf("POST /v1/ai/ask with %s's entities-only token = %d: %.300s", tn.slug, code, raw)
	}
	ans := decodeAnswer(t, "entities-only answer", raw)
	for _, e := range ans.Evidence {
		if e.Domain != "entities" {
			t.Errorf("the entities-only answer of %s holds %s evidence %q", tn.slug, e.Domain, e.Title)
		}
	}
	blocked := 0
	for _, step := range ans.InvestigationPlan {
		switch {
		case step.Domain == "entities" && step.Status != "queried":
			t.Errorf("the entities-only answer of %s did not query its incidents: %+v", tn.slug, step)
		case step.Domain != "entities" && step.Status != "blocked":
			t.Errorf("the entities-only answer of %s says %s was %s, want blocked by permission", tn.slug, step.Domain, step.Status)
		case step.Domain != "entities":
			blocked++
		}
	}
	if blocked == 0 || !ans.RootCauseGrounded || !strings.Contains(ans.RootCause, "AS"+strconv.Itoa(hijackerA)) {
		t.Errorf("the entities-only answer of %s: %d steps blocked, root cause %q grounded=%v; want the hijack from the incident and the rest blocked",
			tn.slug, blocked, ans.RootCause, ans.RootCauseGrounded)
	}

	// ai.query without test.read: the path source is refused, topology is not.
	noTestRead := tn.mintToken(t, st, "receipt-no-test-read", "tenant.read", "ai.query", "topology.read")
	if code, raw := bearer(t, st, noTestRead, http.MethodPost, "/v1/explorer/query", pathQuery(tn.pathTarget)); code != http.StatusForbidden {
		t.Errorf("POST /v1/explorer/query (path) with a %s token lacking test.read = %d, want 403: %.300s", tn.slug, code, raw)
	}
	if code, raw := bearer(t, st, noTestRead, http.MethodPost, "/v1/explorer/query", topologyQuery()); code != http.StatusOK {
		t.Errorf("POST /v1/explorer/query (topology) with a %s token holding topology.read = %d, want 200: %.300s", tn.slug, code, raw)
	} else {
		tn.keep(raw)
	}

	// Tenant first: the other tenant's incident is not in this tenant's
	// scope, and no request picks its own scope.
	foreign := tn.do(t, st, http.MethodPost, "/v1/ai/ask", map[string]any{
		"question": "What happened in this incident?", "subject": map[string]string{"incident_id": other.incidentID},
	}, nil, http.StatusOK)
	// (The answer echoes the id the caller sent in its plan, so it is not
	// byte-searched; what matters is that no evidence came back.)
	if f := decodeAnswer(t, "foreign incident answer", foreign); !f.InsufficientEvidence || len(f.Evidence) != 0 {
		t.Errorf("%s asking about %s's incident %s got evidence %+v, want none", tn.slug, other.slug, other.incidentID, f.Evidence)
	}
	for _, key := range []string{"tenant_id", "tenant"} {
		code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/ai/ask", map[string]any{
			"question": tn.question, "subject": map[string]string{key: other.id},
		})
		if code != http.StatusUnprocessableEntity || !strings.Contains(string(raw), "scope comes from authentication") {
			t.Errorf("POST /v1/ai/ask as %s with subject %s=%s's id = %d, want the 422 refusal: %.300s", tn.slug, key, other.slug, code, raw)
		}
	}
	t.Logf("%s: no ai.query -> 403 (API, CLI, Explorer); entities.read only -> %d steps blocked; no test.read -> path 403; %s's incident -> no evidence; tenant in subject -> 422",
		tn.slug, blocked, other.slug)
}

// --- the rendered pages ---

func (tn *rcaTenant) renderAsk(t *testing.T, st *shipped.Stack, other *rcaTenant) {
	t.Helper()
	expect := []string{"Ask probectl", "Built-in · local/air-gapped", "root cause grounded", "Root cause cited:", "Evidence", "bgp"}
	if tn.prefix == prefixA {
		expect = append(expect, prefixA, "AS"+strconv.Itoa(hijackerA), tn.ruleName, "network", "metrics")
	} else {
		expect = append(expect, prefixB, strconv.Itoa(noTransitB), "topology")
	}
	page := testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/ask?question=" + url.QueryEscape(tn.question),
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Ask probectl"},
		Steps:  []testsupport.RenderStep{{Click: "Ask", Expect: expect}},
		Absent: other.identifiers(),
	}
	res := testsupport.RenderUI(t, page)
	tn.keep([]byte(res.Text))
}

func (tn *rcaTenant) renderExplore(t *testing.T, st *shipped.Stack, other *rcaTenant) {
	t.Helper()
	from, to := tn.routingEdge()
	page := testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/explore?template=service-dependencies",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Show service dependencies"},
		Steps:  []testsupport.RenderStep{{Click: "Run query", Expect: []string{from, to, "routing"}}},
		Absent: other.identifiers(),
	}
	res := testsupport.RenderUI(t, page)
	tn.keep([]byte(res.Text))
}

// --- egress ---

// egressRecorder is the deployment's egress proxy as far as the control
// plane knows: it records every request it is asked to carry and forwards
// none.
type egressRecorder struct {
	addr string
	mu   sync.Mutex
	seen []string
}

func startEgressRecorder(t *testing.T) *egressRecorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &egressRecorder{addr: ln.Addr().String()}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, req.Method+" "+req.Host)
		r.mu.Unlock()
		http.Error(w, "the receipt's egress recorder carries nothing", http.StatusForbidden)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return r
}

func (r *egressRecorder) url() string { return "http://" + r.addr }

func (r *egressRecorder) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func checkNoEgress(t *testing.T, st *shipped.Stack, proxy *egressRecorder) {
	t.Helper()
	if seen := proxy.requests(); len(seen) != 0 {
		t.Errorf("the control plane sent %d requests off this host through its egress proxy: %v", len(seen), seen)
	}
	raw, err := os.ReadFile(st.Log)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"ai remote egress`)) {
		t.Errorf("the control plane logged a remote AI egress with the builtin adapter")
	}
	t.Logf("no egress: the recording proxy saw no request; the control plane logged no remote AI egress")
}

// checkRemoteAdapterNeedsConsent redeploys the control plane with a remote
// OpenAI-compatible adapter. No tenant has consented to remote egress, so
// each is refused before anything leaves, and the refusal is audited in the
// tenant's own chain.
func checkRemoteAdapterNeedsConsent(t *testing.T, st *shipped.Stack, proxy *egressRecorder, tenants []*rcaTenant) {
	t.Helper()
	const llmHost = "llm.airca-receipt.example"
	st.RestartControl(t, "control-remote-model", map[string]string{
		"PROBECTL_AI_MODEL_PROVIDER": "openai",
		"PROBECTL_AI_MODEL_ENDPOINT": "https://" + llmHost + "/v1",
		"PROBECTL_AI_MODEL_NAME":     "receipt-model",
		"PROBECTL_AI_EGRESS_ACK":     "yes-send-tenant-data-to-the-remote-model",
	})
	for _, tn := range tenants {
		code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/ai/ask", map[string]any{"question": tn.question})
		if code != http.StatusForbidden || !strings.Contains(string(raw), "egress is disabled for this tenant") {
			t.Errorf("POST /v1/ai/ask as %s (no consent) with a remote adapter = %d, want the 403 consent refusal: %.300s", tn.slug, code, raw)
		}
		var audit struct {
			Items []struct {
				Action string `json:"action"`
			} `json:"items"`
		}
		tn.do(t, st, http.MethodGet, "/v1/audit?limit=200", nil, &audit, http.StatusOK)
		if !slices.ContainsFunc(audit.Items, func(e struct {
			Action string `json:"action"`
		}) bool {
			return e.Action == "ai.remote_egress_denied"
		}) {
			t.Errorf("%s's audit chain holds no ai.remote_egress_denied after the refusal", tn.slug)
		}
	}
	for _, r := range proxy.requests() {
		t.Errorf("the egress proxy was asked to carry %q: tenant data left without consent", r)
	}
	t.Logf("remote adapter (%s) without consent: every tenant refused 403, the refusal audited, nothing sent", llmHost)
}

// --- the services ---

// flapTarget is a tenant's TCP service on loopback that can go down.
type flapTarget struct {
	addr string
	mu   sync.Mutex
	ln   net.Listener
}

func newFlapTarget(t *testing.T) *flapTarget {
	t.Helper()
	ln, err := net.Listen("tcp", serviceHost+":0")
	if err != nil {
		t.Fatal(err)
	}
	f := &flapTarget{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { f.down(t) })
	return f
}

func (f *flapTarget) down(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		_ = f.ln.Close()
		f.ln = nil
	}
}

// --- helpers ---

func promValue(t *testing.T, query string) (float64, bool) {
	t.Helper()
	resp, err := http.Get(strings.TrimRight(os.Getenv("PROBECTL_PROM_URL"), "/") + "/api/v1/query?query=" + url.QueryEscape(query))
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Result []struct {
				Value [2]any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || len(out.Data.Result) == 0 {
		return 0, false
	}
	s, _ := out.Data.Result[0].Value[1].(string)
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}

// analyzerPython is the interpreter the analyzer sidecar runs: CI's python3
// with the hash-locked runtime (analyzer/requirements.lock) installed, or
// PROBECTL_TEST_BGP_ANALYZER_PYTHON.
func analyzerPython(t *testing.T) string {
	t.Helper()
	python := os.Getenv("PROBECTL_TEST_BGP_ANALYZER_PYTHON")
	if python == "" {
		python = "python3"
	}
	if out, err := exec.Command(python, "-c", "import structlog, websockets").CombinedOutput(); err != nil {
		testsupport.SkipOrFatal(t, "the BGP analyzer needs %s with analyzer/requirements.lock installed (CI: pip install --require-hashes -r analyzer/requirements.lock): %v %s", python, err, out)
	}
	return python
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
