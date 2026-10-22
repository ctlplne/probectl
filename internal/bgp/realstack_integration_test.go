// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"context"
	"crypto/tls"
	"encoding/hex"
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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// frrImage is the real BGP speaker of the deterministic leg: FRRouting, the
// router the BMP documentation is verified with, pinned by digest.
const frrImage = "quay.io/frrouting/frr:10.3.1@sha256:f90d26a9fd5c14fc5795a73b4254ac88bc3186c45bbeb220a225fb6182de812c"

// The lab's routing plan. Every prefix and ASN is from the documentation or
// private ranges, so nothing here can be mistaken for the live internet.
const (
	edgeASN = 65010 // "the internet": the upstream that announces every route
	rrcASN  = 64511 // the lab route collector, which records MRT like a RIS RRC
	rtrAASN = 64601 // tenant A's own router (BMP)
	rtrBASN = 64602 // tenant B's own router (BMP)

	prefixA   = "203.0.113.0/24" // tenant A's address block
	originA   = 64500            // ...and the AS that should originate it
	hijackerA = 65021            // the AS that hijacks it

	prefixB       = "198.51.100.0/24" // tenant B's block, multi-homed
	originB       = 64501
	originB2      = 64502
	noTransitB    = 64666 // must never carry B's traffic: seeing it is a leak
	prefixDecoy   = "192.0.2.0/24"
	originDecoy   = 65099
	originDecoyTo = 65098

	// labCollector is the analyzer's collector label for the lab's route
	// collector (a RIS RRC's name, in the real deployment).
	labCollector = "lab-rrc"

	// The live leg watches 1.0.0.0/16 (APNIC; it covers Cloudflare's
	// 1.0.0.0/24) and declares AS64496, a documentation ASN that originates
	// nothing, as its only expected origin. Every real announcement under the
	// block is therefore a "possible hijack" for this tenant: the leg proves a
	// live RIS update flows end to end, not that anything was hijacked.
	livePrefix      = "1.0.0.0/16"
	liveExpectedASN = 64496
	liveWindow      = 120 * time.Second
)

// TestBGPMonitoringRealStack is the real-stack receipt for BGP monitoring
// (F6): "us or the internet?", answered per tenant through the public API,
// the CLI and the rendered BGP page, from input that went through the shipped
// collectors. Two input legs, each named in the test output:
//
// DETERMINISTIC (binding). Real BGP speakers: four FRRouting containers on a
// private docker network. "edge" (AS65010) plays the internet and announces
// A's prefix (origin AS64500), B's prefix (origin AS64501) and a decoy
// nobody watches. "rrc" (AS64511) is the lab route collector and records
// every UPDATE it receives as MRT (RFC 6396), as a RIS RRC does. "rtr-a" and
// "rtr-b" are A's and B's own routers; edge exports only the tenant's prefix
// to each, and each router exports BMP to its tenant's shipped
// probectl-bmp-listener through a TLS sidecar presenting the router's
// registry-issued SVID. After every router holds its baseline, edge changes
// three routes with real BGP UPDATEs: A's prefix is hijacked (origin
// AS64500 -> AS65021, RPKI-invalid against A's ROA), B's prefix leaks
// (now via no-transit AS64666, from its second origin AS64502), and the
// decoy changes origin. Each tenant's shipped analyzer sidecar
// (probectl-control bgp-analyzer, Python under the Go tenant-bound bridge)
// then reads the collector's MRT with that tenant's own watch config, as the
// per-tenant ingest ADR prescribes (docs/adr/bgp-ingest-model.md).
//
// LIVE (best effort). Tenant C's analyzer sidecar subscribes to RIPE RIS
// Live (wss, TLS validated by the client) for livePrefix. If RIS Live is
// unreachable, or sends no update for the block within liveWindow, the leg
// says so and stands down; the deterministic leg remains the proof. It fails
// the receipt only when a live event was bridged onto the bus and never
// reached the tenant's surfaces.
//
// The stack is the shipped control plane on the four-store profile
// (shipped.Start): least-privilege PostgreSQL, Kafka with strict tenant
// lanes, ClickHouse, Prometheus, TLS everywhere, the real IdP (production
// session auth in Chromium) and an MSP license. A and C are pooled, B is
// hybrid.
//
//  1. Each tenant registers its BGP source (A through the API, B and C with
//     `probectl agent enroll-token` + `probectl bgp setup`) and gets its own
//     lane; A and B register their router with a router-owned CSR (A through
//     the API, B with `probectl collector register`).
//  2. A's and B's listeners record their router's baseline; edge injects.
//  3. GET /v1/bgp/events, `probectl bgp events` and the rendered /planes/bgp
//     show A its hijack (analyzer: possible_hijack, origin_change and
//     rpki_invalid seen by lab-rrc; BMP: origin_change seen by A's
//     listener from rtr-a) and B its leak (analyzer: possible_leak and
//     origin_change; BMP: origin_change seen by B's listener from rtr-b).
//     Every event is for the tenant's own prefix; nobody sees the decoy; the
//     prefix and ASN filters find nothing of another tenant's. As the app
//     role, a predicate-free count of the BGP signals scoped to A (or B) is
//     exactly A's (or B's): PostgreSQL row security, not the query, isolates.
//  4. C (live leg) sees real RIS announcements under livePrefix, each named
//     by the RIS collector that recorded it (DPR-294), and nothing of A's
//     or B's; A and B see nothing of C's.
func TestBGPMonitoringRealStack(t *testing.T) {
	python := analyzerPython(t)
	lab := startRoutingLab(t)
	st := shipped.Start(t, shipped.Options{Name: "bgpmon", TenantBand: 4})
	op := st.OnboardOperator(t, "root@msp-bgp.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)

	A := &bgpTenant{slug: "bgp-acme-" + run, name: "BGP Acme", model: "pooled", admin: "ada@acme.example",
		prefix: prefixA, router: "rtr-a"}
	B := &bgpTenant{slug: "bgp-globex-" + run, name: "BGP Globex", model: "hybrid", admin: "bob@globex.example",
		prefix: prefixB, router: "rtr-b"}
	C := &bgpTenant{slug: "bgp-initech-" + run, name: "BGP Initech", model: "pooled", admin: "carla@acme.example",
		prefix: livePrefix}
	tenants := []*bgpTenant{A, B, C}
	for _, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id = row.ID
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "agent.write", "events.read")
	}

	// 1. Each tenant's BGP source, through the API (A) or the CLI (B, C).
	A.setupAPI(t, st)
	B.setupCLI(t, st)
	C.setupCLI(t, st)
	live := startLiveLeg(t, st, python, C)

	// 2. Each router's BMP feed reaches its tenant's listener; then the
	// internet changes.
	A.registerRouterAPI(t, st)
	B.registerRouterCLI(t, st)
	logins := bmpLogins(t, st)
	for _, tn := range []*bgpTenant{A, B} {
		tn.startListener(t, st, logins)
		bridgeBMP(t, lab.bmpAddr(t, tn.router), tn.listenAddr, tn.routerTLS(t, st))
		tn.awaitListener(t, "the baseline of "+tn.router, "route_observation")
	}
	lab.inject(t)
	for _, tn := range []*bgpTenant{A, B} {
		tn.awaitListener(t, "the origin change "+tn.router+" saw", "origin_change")
	}

	// The lab collector's MRT, read by each tenant's own analyzer sidecar.
	mrt := lab.collectorMRT(t)
	A.watch = map[string]any{"prefix": prefixA, "expected_origins": []int{originA}}
	A.vrp = []map[string]any{{"prefix": prefixA, "maxLength": 24, "asn": "AS" + strconv.Itoa(originA)}}
	B.watch = map[string]any{"prefix": prefixB, "expected_origins": []int{originB, originB2}, "no_transit": []int{noTransitB}}
	for _, tn := range []*bgpTenant{A, B} {
		tn.runAnalyzer(t, st, python, mrt)
	}

	// 3. Each tenant's surfaces show its own anomaly, and only its own.
	A.want = []wantEvent{
		{kind: "bgp.possible_hijack", collector: labCollector, origin: hijackerA, rpki: "RPKI_STATUS_INVALID", input: "deterministic: FRR -> MRT -> analyzer"},
		{kind: "bgp.origin_change", collector: labCollector, origin: hijackerA, was: originA, input: "deterministic: FRR -> MRT -> analyzer"},
		{kind: "bgp.rpki_invalid", collector: labCollector, origin: hijackerA, rpki: "RPKI_STATUS_INVALID", input: "deterministic: FRR -> MRT -> analyzer"},
		{kind: "bgp.origin_change", collector: A.bmpSource(), origin: hijackerA, was: originA, input: "deterministic: FRR rtr-a -> BMP -> listener"},
	}
	B.want = []wantEvent{
		{kind: "bgp.possible_leak", collector: labCollector, origin: originB2, path: fmt.Sprintf("%d,%d,%d", edgeASN, noTransitB, originB2), input: "deterministic: FRR -> MRT -> analyzer"},
		{kind: "bgp.origin_change", collector: labCollector, origin: originB2, was: originB, input: "deterministic: FRR -> MRT -> analyzer"},
		{kind: "bgp.origin_change", collector: B.bmpSource(), origin: originB2, was: originB, input: "deterministic: FRR rtr-b -> BMP -> listener"},
	}
	for _, tn := range []*bgpTenant{A, B} {
		tn.awaitEvents(t, st, 60*time.Second)
	}
	live.conclude(t, st)
	for _, tn := range tenants {
		tn.checkSurfaces(t, st, tenants)
	}
	for _, tn := range []*bgpTenant{A, B} {
		own, seen, total := signalCounts(t, st, tn.id)
		if seen != own || seen != len(tn.events) || own >= total {
			t.Errorf("as the app role scoped to %s, a predicate-free count of BGP signals saw %d; the tenant owns %d (its API lists %d) of %d: the storage layer is not enforcing tenant isolation",
				tn.slug, seen, own, len(tn.events), total)
		}
	}

	// The rendered BGP page, as each tenant's admin.
	for _, tn := range tenants {
		if tn == C && !live.ran {
			continue
		}
		tn.renderPage(t, st, tenants)
	}
}

// --- the tenants ---

type wantEvent struct {
	kind, collector, rpki, path, input string
	origin, was                        int
}

type bgpEvent struct {
	ID         string            `json:"id"`
	IncidentID string            `json:"incident_id"`
	Kind       string            `json:"kind"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Prefix     string            `json:"prefix"`
	Attributes map[string]string `json:"attributes"`
	OccurredAt time.Time         `json:"occurred_at"`
}

type bgpTenant struct {
	slug, name, model, admin string
	prefix, router           string
	id, cookie, token        string
	collectorID, lane        string
	routerID, routerCert     string
	routerKey                []byte
	listenAddr, listenerLog  string
	watch                    map[string]any
	vrp                      []map[string]any
	want                     []wantEvent
	events                   []bgpEvent
}

func (tn *bgpTenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

func (tn *bgpTenant) do(t *testing.T, st *shipped.Stack, method, route string, body, out any, want int) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, method, route, body)
	if code != want || (out != nil && json.Unmarshal(raw, out) != nil) {
		t.Fatalf("%s %s as %s = %d (want %d): %.400s", method, route, tn.slug, code, want, raw)
	}
}

type registration struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	Plane    string `json:"plane"`
	Config   struct {
		Env            map[string]string `json:"env"`
		StartupCommand string            `json:"startup_command"`
	} `json:"config"`
	SVID *struct {
		CertPEM  string `json:"cert_pem"`
		SPIFFEID string `json:"spiffe_id"`
		TenantID string `json:"tenant_id"`
		Plane    string `json:"plane"`
	} `json:"svid"`
}

// bindSource checks a plane=bgp registration and keeps the collector id and
// the tenant's lane it hands out.
func (tn *bgpTenant) bindSource(t *testing.T, surface string, reg registration) {
	t.Helper()
	env := reg.Config.Env
	if reg.TenantID != tn.id || reg.Plane != "bgp" || reg.AgentID == "" || reg.Config.StartupCommand != "probectl-bmp-listener" ||
		env["PROBECTL_BMP_TENANT_ID"] != tn.id || env["PROBECTL_BMP_AGENT_ID"] != reg.AgentID || env["PROBECTL_BMP_COLLECTOR"] != reg.AgentID ||
		env["PROBECTL_BMP_BUS_NAMESPACE"] == "" {
		t.Fatalf("%s as %s returned %+v, want a bgp source bound to the tenant with its lane", surface, tn.slug, reg)
	}
	tn.collectorID, tn.lane = reg.AgentID, env["PROBECTL_BMP_BUS_NAMESPACE"]
	t.Logf("%s registered BGP source %s on lane %s (%s)", tn.slug, tn.collectorID, tn.lane, surface)
}

// setupAPI registers A's BGP source through the public API.
func (tn *bgpTenant) setupAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var reg registration
	tn.do(t, st, http.MethodPost, "/v1/collectors/register",
		map[string]any{"token": tn.mintTokenAPI(t, st, "lab-rrc"), "plane": "bgp", "hostname": labCollector}, &reg, http.StatusCreated)
	tn.bindSource(t, "POST /v1/collectors/register", reg)
}

func (tn *bgpTenant) mintTokenAPI(t *testing.T, st *shipped.Stack, name string) string {
	t.Helper()
	var tok struct{ Token string }
	tn.do(t, st, http.MethodPost, "/v1/agents/enroll-tokens", map[string]any{"name": name, "ttl_seconds": 600}, &tok, http.StatusCreated)
	return tok.Token
}

func (tn *bgpTenant) mintTokenCLI(t *testing.T, st *shipped.Stack, name string) string {
	t.Helper()
	var tok struct{ Token string }
	st.MustCLI(t, tn.env(), &tok, "agent", "enroll-token", "--body", fmt.Sprintf(`{"name":%q,"ttl_seconds":600}`, name))
	return tok.Token
}

// setupCLI registers the tenant's BGP source with `probectl bgp setup`.
func (tn *bgpTenant) setupCLI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var reg registration
	st.MustCLI(t, tn.env(), &reg, "bgp", "setup", "--body-file", st.SecretFile(t,
		map[string]any{"token": tn.mintTokenCLI(t, st, "lab-rrc"), "plane": "bgp", "hostname": labCollector}))
	tn.bindSource(t, "probectl bgp setup", reg)
}

// bindRouter keeps the router's registry-issued SVID; its key never left the
// "router" (this test).
func (tn *bgpTenant) bindRouter(t *testing.T, surface string, reg registration) {
	t.Helper()
	if reg.SVID == nil || reg.SVID.TenantID != tn.id || reg.SVID.Plane != "bmp" || reg.SVID.CertPEM == "" ||
		reg.SVID.SPIFFEID != crypto.BMPSPIFFEID(tn.id, reg.AgentID) {
		t.Fatalf("%s as %s returned %+v, want a bmp SVID for the tenant's router", surface, tn.slug, reg)
	}
	tn.routerID, tn.routerCert = reg.AgentID, reg.SVID.CertPEM
}

func (tn *bgpTenant) routerCSR(t *testing.T) string {
	t.Helper()
	csr, key, err := crypto.CreateCSR(tn.router)
	if err != nil {
		t.Fatal(err)
	}
	tn.routerKey = key
	return string(csr)
}

func (tn *bgpTenant) registerRouterAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var reg registration
	tn.do(t, st, http.MethodPost, "/v1/collectors/register", map[string]any{
		"token": tn.mintTokenAPI(t, st, tn.router), "plane": "bmp", "hostname": tn.router, "csr_pem": tn.routerCSR(t),
	}, &reg, http.StatusCreated)
	tn.bindRouter(t, "POST /v1/collectors/register (bmp)", reg)
}

func (tn *bgpTenant) registerRouterCLI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var reg registration
	st.MustCLI(t, tn.env(), &reg, "collector", "register", "--body-file", st.SecretFile(t, map[string]any{
		"token": tn.mintTokenCLI(t, st, tn.router), "plane": "bmp", "hostname": tn.router, "csr_pem": tn.routerCSR(t),
	}))
	tn.bindRouter(t, "probectl collector register (bmp)", reg)
}

// routerTLS is the router's sidecar identity: its SVID and its own key,
// verifying the listener against the deployment CA.
func (tn *bgpTenant) routerTLS(t *testing.T, st *shipped.Stack) *tls.Config {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "router.crt"), filepath.Join(dir, "router.key")
	if err := os.WriteFile(cert, []byte(tn.routerCert), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, tn.routerKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := crypto.ClientMTLSConfig(cert, key, st.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerName = "localhost"
	return cfg
}

// startListener runs the tenant's shipped BMP listener exactly as its
// registration hints say, with this deployment's paths and addresses.
func (tn *bgpTenant) startListener(t *testing.T, st *shipped.Stack, logins bmpDSNs) {
	t.Helper()
	tn.listenAddr = shipped.FreeAddr(t)
	label := "bmp-listener-" + tn.router
	tn.listenerLog = st.StartProcess(t, label, st.Binary(t, "probectl-bmp-listener"), nil, []string{
		"PROBECTL_BMP_LISTEN_ADDR=" + tn.listenAddr,
		"PROBECTL_BMP_TLS_CERT_FILE=" + st.ServerCert,
		"PROBECTL_BMP_TLS_KEY_FILE=" + st.ServerKey,
		"PROBECTL_BMP_TLS_CA_FILE=" + st.AgentCAFile,
		"PROBECTL_BMP_DATABASE_URL=" + logins.registry,
		"PROBECTL_BMP_REVOCATION_DATABASE_URL=" + logins.revocation,
		"PROBECTL_BMP_TENANT_ID=" + tn.id,
		"PROBECTL_BMP_AGENT_ID=" + tn.collectorID,
		"PROBECTL_BMP_COLLECTOR=" + tn.collectorID,
		"PROBECTL_BMP_BUS_NAMESPACE=" + tn.lane,
		"PROBECTL_BMP_BUS_MODE=kafka",
		"PROBECTL_BMP_BUS_BROKERS=" + strings.Join(testsupport.KafkaBrokers(), ","),
		"PROBECTL_BMP_BUS_ALLOW_PLAINTEXT=true", // the dev stack's Kafka is plaintext
		"PROBECTL_BMP_METRICS_ADDR=" + shipped.FreeAddr(t),
	})
}

// awaitListener waits for the listener to publish an event of kind for the
// tenant's prefix.
func (tn *bgpTenant) awaitListener(t *testing.T, what, kind string) {
	t.Helper()
	shipped.Await(t, what, 90*time.Second, func() bool {
		raw, _ := os.ReadFile(tn.listenerLog)
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, `"bmp route event published"`) && strings.Contains(line, `"event_type":"`+kind+`"`) &&
				strings.Contains(line, `"prefix":"`+tn.prefix+`"`) && strings.Contains(line, `"tenant_id":"`+tn.id+`"`) {
				return true
			}
		}
		return false
	})
}

// analyzerConfig writes the tenant's watch config: the analyzer JSON the
// sidecar's PROBECTL_BGP_ANALYZER_CONFIG names.
func (tn *bgpTenant) analyzerConfig(t *testing.T, collector string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := map[string]any{"tenant_id": tn.id, "collector": collector, "monitored_prefixes": []map[string]any{tn.watch}}
	if tn.vrp != nil {
		vrp := filepath.Join(dir, "vrp.json")
		writeJSON(t, vrp, map[string]any{"roas": tn.vrp})
		cfg["rpki_vrp_file"] = vrp
	}
	path := filepath.Join(dir, "analyzer.json")
	writeJSON(t, path, cfg)
	return path
}

// analyzerEnv is the shipped sidecar's environment for one tenant.
func (tn *bgpTenant) analyzerEnv(st *shipped.Stack, python, config, source, file string) []string {
	env := []string{
		"PROBECTL_BGP_ANALYZER_CONFIG=" + config,
		"PROBECTL_BGP_ANALYZER_SOURCE=" + source,
		"PROBECTL_BGP_ANALYZER_BUS_NAMESPACE=" + tn.lane,
		"PROBECTL_BGP_ANALYZER_PYTHON=" + python,
		"PYTHONPATH=" + filepath.Join(st.Root, "analyzer"),
		"PROBECTL_BUS_MODE=kafka",
		"PROBECTL_BUS_BROKERS=" + strings.Join(testsupport.KafkaBrokers(), ","),
		"PROBECTL_BUS_ALLOW_PLAINTEXT=true", // the dev stack's Kafka is plaintext
	}
	if file != "" {
		env = append(env, "PROBECTL_BGP_ANALYZER_SOURCE_FILE="+file)
	}
	return env
}

// runAnalyzer runs the tenant's shipped analyzer sidecar once over the lab
// collector's MRT (a finite source: it publishes and exits).
func (tn *bgpTenant) runAnalyzer(t *testing.T, st *shipped.Stack, python, mrt string) {
	t.Helper()
	cmd := exec.Command(st.Control, "bgp-analyzer")
	cmd.Dir = st.Dir
	cmd.Env = append(os.Environ(), tn.analyzerEnv(st, python, tn.analyzerConfig(t, labCollector), "mrt", mrt)...)
	out, err := cmd.CombinedOutput()
	logPath := filepath.Join(st.Dir, "bgp-analyzer-"+tn.slug+".log")
	_ = os.WriteFile(logPath, out, 0o600)
	if err != nil || !strings.Contains(string(out), `"bgp analyzer completed"`) {
		t.Fatalf("probectl-control bgp-analyzer (mrt) for %s: %v\n%s", tn.slug, err, out)
	}
	t.Logf("[deterministic] %s's analyzer sidecar read the lab collector's MRT with its watch config %v", tn.slug, tn.watch)
}

// listEvents reads the tenant's BGP events through the API.
func (tn *bgpTenant) listEvents(t *testing.T, st *shipped.Stack, query string) []bgpEvent {
	t.Helper()
	var out struct {
		Items      []bgpEvent `json:"items"`
		BGPRunning bool       `json:"bgp_running"`
	}
	tn.do(t, st, http.MethodGet, "/v1/bgp/events?limit=200"+query, nil, &out, http.StatusOK)
	if !out.BGPRunning {
		t.Fatalf("GET /v1/bgp/events as %s says bgp_running=false", tn.slug)
	}
	return out.Items
}

// awaitEvents waits until the tenant's API lists every event it should.
func (tn *bgpTenant) awaitEvents(t *testing.T, st *shipped.Stack, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		tn.events = tn.listEvents(t, st, "")
		missing := tn.missing(tn.events)
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET /v1/bgp/events as %s never listed %+v; it lists %s", tn.slug, missing, describe(tn.events))
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, w := range tn.want {
		t.Logf("[%s] %s sees %s on %s (origin AS%d) seen by %s", w.input, tn.slug, w.kind, tn.prefix, w.origin, w.collector)
	}
}

func (tn *bgpTenant) missing(events []bgpEvent) []wantEvent {
	var out []wantEvent
	for _, w := range tn.want {
		if !slices.ContainsFunc(events, func(e bgpEvent) bool { return w.matches(tn.prefix, e) }) {
			out = append(out, w)
		}
	}
	return out
}

func (w wantEvent) matches(prefix string, e bgpEvent) bool {
	a := e.Attributes
	return e.Kind == w.kind && e.Prefix == prefix && a["collector"] == w.collector &&
		a["new_origin_asn"] == strconv.Itoa(w.origin) &&
		(w.was == 0 || a["old_origin_asn"] == strconv.Itoa(w.was)) &&
		(w.rpki == "" || a["rpki_status"] == w.rpki) &&
		(w.path == "" || a["new_as_path"] == w.path)
}

// checkSurfaces asserts the tenant's API and CLI hold its own events and
// nothing of another tenant's, and that the filters cannot reach across.
func (tn *bgpTenant) checkSurfaces(t *testing.T, st *shipped.Stack, tenants []*bgpTenant) {
	t.Helper()
	api := tn.listEvents(t, st, "")
	var cli struct{ Items []bgpEvent }
	st.MustCLI(t, tn.env(), &cli, "bgp", "events", "--query", "limit=200")
	for surface, events := range map[string][]bgpEvent{"GET /v1/bgp/events": api, "probectl bgp events": cli.Items} {
		if missing := tn.missing(events); len(missing) > 0 {
			t.Errorf("%s as %s misses %+v; it lists %s", surface, tn.slug, missing, describe(events))
		}
		for _, e := range events {
			if !tn.owns(e) {
				t.Errorf("%s as %s lists an event outside the tenant's watch config and routers: %s", surface, tn.slug, describe([]bgpEvent{e}))
			}
		}
	}
	for _, other := range tenants {
		if other == tn {
			continue
		}
		q := "&prefix=" + url.QueryEscape(other.prefix)
		if got := tn.listEvents(t, st, q); len(got) != 0 {
			t.Errorf("GET /v1/bgp/events?prefix=%s (%s's prefix) as %s lists %s", other.prefix, other.slug, tn.slug, describe(got))
		}
		var filtered struct{ Items []bgpEvent }
		st.MustCLI(t, tn.env(), &filtered, "bgp", "events", "--query", "prefix="+other.prefix)
		if len(filtered.Items) != 0 {
			t.Errorf("probectl bgp events --query prefix=%s (%s's prefix) as %s lists %s", other.prefix, other.slug, tn.slug, describe(filtered.Items))
		}
	}
	for _, q := range []string{"&prefix=" + url.QueryEscape(prefixDecoy), "&asn=AS" + strconv.Itoa(originDecoyTo)} {
		if got := tn.listEvents(t, st, q); len(got) != 0 {
			t.Errorf("GET /v1/bgp/events?%s (the decoy nobody watches) as %s lists %s", q[1:], tn.slug, describe(got))
		}
	}
	hijack := tn.listEvents(t, st, "&asn=AS"+strconv.Itoa(hijackerA))
	if (tn.prefix == prefixA) != (len(hijack) > 0) {
		t.Errorf("GET /v1/bgp/events?asn=AS%d as %s lists %s; only %s's prefix was hijacked by it", hijackerA, tn.slug, describe(hijack), prefixA)
	}
	tn.events = api
}

// owns reports whether e is for the tenant's own watch config (or, for the
// live tenant, inside its watched block) and from the tenant's own sources.
func (tn *bgpTenant) owns(e bgpEvent) bool {
	if tn.prefix == livePrefix {
		return inLiveBlock(e.Prefix) && risCollector.MatchString(e.Attributes["collector"])
	}
	c := e.Attributes["collector"]
	return e.Prefix == tn.prefix && (c == labCollector || c == tn.bmpSource())
}

// bmpSource is the collector a tenant's BMP events name: its listener's
// registered collector id and the router that reported the route.
func (tn *bgpTenant) bmpSource() string { return tn.collectorID + "/" + tn.routerID }

// renderPage renders /planes/bgp as the tenant's admin.
func (tn *bgpTenant) renderPage(t *testing.T, st *shipped.Stack, tenants []*bgpTenant) {
	t.Helper()
	page := testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/planes/bgp",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Routing anomalies"},
	}
	switch tn.prefix {
	case prefixA:
		page.Expect = append(page.Expect, prefixA, "Possible hijack", "Origin change", "RPKI invalid",
			"AS65021", "AS64500 → AS65021", "Invalid", labCollector, tn.collectorID)
		page.Absent = append(page.Absent, "Possible leak")
	case prefixB:
		page.Expect = append(page.Expect, prefixB, "Possible leak", "Origin change",
			"AS64501 → AS64502", "65010 64666 64502", labCollector, tn.collectorID)
		page.Absent = append(page.Absent, "Possible hijack")
	default:
		newest := tn.events[0]
		page.Expect = append(page.Expect, newest.Prefix, "Possible hijack", newest.Attributes["collector"])
	}
	page.Absent = append(page.Absent, prefixDecoy, "AS"+strconv.Itoa(originDecoyTo))
	for _, other := range tenants {
		if other == tn {
			continue
		}
		page.Absent = append(page.Absent, other.prefix, other.name)
		if other.collectorID != "" {
			page.Absent = append(page.Absent, other.collectorID)
		}
		if other.prefix == livePrefix && len(other.events) > 0 {
			page.Absent = append(page.Absent, other.events[0].Prefix)
		}
	}
	testsupport.RenderUI(t, page)
}

func describe(events []bgpEvent) string {
	parts := make([]string, 0, len(events))
	for _, e := range events {
		parts = append(parts, fmt.Sprintf("%s %s origin=%s was=%s collector=%s rpki=%s path=%s",
			e.Kind, e.Prefix, e.Attributes["new_origin_asn"], e.Attributes["old_origin_asn"],
			e.Attributes["collector"], e.Attributes["rpki_status"], e.Attributes["new_as_path"]))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
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

// --- storage-layer isolation ---

type bmpDSNs struct{ registry, revocation string }

// bmpLogins creates the two PostgreSQL logins the BMP listener needs, as
// docs/configuration.md tells the operator to: one a member of probectl_app
// for the tenant-scoped identity lookup, one granted only the execute-only
// revocation reader role.
func bmpLogins(t *testing.T, st *shipped.Stack) bmpDSNs {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	login := func(role, grant string) string {
		pw, err := crypto.Random(16)
		if err != nil {
			t.Fatal(err)
		}
		password := hex.EncodeToString(pw)
		quoted := pgx.Identifier{role}.Sanitize()
		for _, stmt := range []string{
			`CREATE ROLE ` + quoted + ` LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '` + password + `'`,
			`GRANT ` + grant + ` TO ` + quoted,
		} {
			if _, err := pool.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s: %v", strings.SplitN(stmt, " PASSWORD", 2)[0], err)
			}
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+quoted) })
		u, err := url.Parse(st.AdminDSN)
		if err != nil {
			t.Fatal(err)
		}
		u.User = url.UserPassword(role, password)
		return u.String()
	}
	dsns := bmpDSNs{
		registry:   login("bmp_registry_"+suffix, "probectl_app"),
		revocation: login("bmp_revocation_"+suffix, "probectl_bmp_revocation_reader"),
	}
	if !strings.Contains(dsns.registry, "sslmode=verify-full") {
		testsupport.SkipOrFatal(t, "the BMP listener requires sslmode=verify-full; serve PostgreSQL over TLS (CI: scripts/ci_pg_tls.sh) and set PROBECTL_DATABASE_URL to a verify-full DSN")
	}
	return dsns
}

// signalCounts counts BGP signals as the app role every tenant read runs as,
// scoped to tenant by the per-transaction setting and with NO tenant_id
// predicate of its own (what PostgreSQL's row security lets a tenant read
// see), next to the tenant's own rows and every tenant's, counted as the
// privileged login.
func signalCounts(t *testing.T, st *shipped.Stack, tenant string) (own, seen, total int) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	const q = `SELECT count(*) FROM incident_signals WHERE plane = 'bgp'`
	if err := conn.QueryRow(ctx, q+` AND tenant_id = $1`, tenant).Scan(&own); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, q).Scan(&total); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, q).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	return own, seen, total
}

// --- the live leg ---

var risCollector = regexp.MustCompile(`^rrc\d+\.ripe\.net$`)

func inLiveBlock(prefix string) bool {
	p, err := netip.ParsePrefix(prefix)
	block := netip.MustParsePrefix(livePrefix)
	return err == nil && p.Bits() >= block.Bits() && block.Contains(p.Addr())
}

type liveLeg struct {
	tn      *bgpTenant
	label   string
	log     string
	started time.Time
	ran     bool
}

// startLiveLeg starts tenant C's analyzer sidecar on RIS Live. It runs while
// the deterministic leg does; conclude decides what it proved.
func startLiveLeg(t *testing.T, st *shipped.Stack, python string, tn *bgpTenant) *liveLeg {
	t.Helper()
	leg := &liveLeg{tn: tn, label: "bgp-analyzer-live"}
	if v := os.Getenv("PROBECTL_TEST_BGP_RIS_LIVE"); v == "0" || v == "off" {
		t.Logf("[live] LIVE LEG SKIPPED: PROBECTL_TEST_BGP_RIS_LIVE=%s", v)
		return leg
	}
	tn.watch = map[string]any{"prefix": livePrefix, "expected_origins": []int{liveExpectedASN}}
	// collector "" subscribes to every RIS collector; each event names the
	// one that recorded it (DPR-294).
	config := tn.analyzerConfig(t, "")
	leg.started = time.Now()
	leg.log = st.StartProcess(t, leg.label, st.Control, []string{"bgp-analyzer"},
		tn.analyzerEnv(st, python, config, "ris-live", ""))
	return leg
}

// conclude waits for a live event in C's API, then stops the sidecar and
// lets the consumer drain. No live input is a stated skip of this leg only.
func (leg *liveLeg) conclude(t *testing.T, st *shipped.Stack) {
	t.Helper()
	if leg.log == "" {
		return
	}
	tn := leg.tn
	deadline := leg.started.Add(liveWindow)
	for time.Now().Before(deadline) && len(tn.listEvents(t, st, "")) == 0 {
		time.Sleep(time.Second)
	}
	st.Stop(t, leg.label)
	raw, _ := os.ReadFile(leg.log)
	logText := string(raw)
	bridged := strings.Contains(logText, `"bgp event bridged"`)
	var events []bgpEvent
	shipped.Await(t, "the live events to settle in "+tn.slug+"'s read model", 60*time.Second, func() bool {
		before := len(events)
		events = tn.listEvents(t, st, "")
		if bridged && len(events) == 0 {
			return false
		}
		time.Sleep(2 * time.Second)
		return len(events) == before && len(tn.listEvents(t, st, "")) == len(events)
	})
	tn.events = events
	switch {
	case len(events) > 0:
		leg.ran = true
		e := events[0]
		t.Logf("[live] LIVE LEG RAN: %s sees %d RIS Live announcement(s) under %s; newest: %s %s from AS%s (peer AS%s %s) recorded by %s at %s",
			tn.slug, len(events), livePrefix, e.Kind, e.Prefix, e.Attributes["new_origin_asn"], e.Attributes["peer_asn"],
			e.Attributes["peer_address"], e.Attributes["collector"], e.OccurredAt.Format(time.RFC3339))
		for _, ev := range events {
			if ev.Kind != "bgp.possible_hijack" || !inLiveBlock(ev.Prefix) || !risCollector.MatchString(ev.Attributes["collector"]) ||
				ev.Attributes["expected_origins"] != strconv.Itoa(liveExpectedASN) || time.Since(ev.OccurredAt) > 30*time.Minute {
				t.Errorf("[live] %s's live event is not a recent RIS Live announcement under %s: %s", tn.slug, livePrefix, describe([]bgpEvent{ev}))
			}
		}
	case bridged:
		t.Errorf("[live] RIS Live events were bridged onto %s's lane but never reached its API:\n%s", tn.slug, tailLines(logText, 30))
	case !strings.Contains(logText, "RIS Live connected"):
		t.Logf("[live] LIVE LEG SKIPPED: RIS Live (wss://ris-live.ripe.net) was unreachable from this host within %s; the deterministic leg is the proof.\n%s", liveWindow, tailLines(logText, 10))
	default:
		t.Logf("[live] LIVE LEG SKIPPED: RIS Live connected but sent no announcement under %s within %s; the deterministic leg is the proof.", livePrefix, liveWindow)
	}
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// --- the BMP sidecar ---

// bridgeBMP stands in for the router's TLS sidecar (docs/bgp.md, "Routers
// without native BMP-over-TLS"): FRR exports plaintext BMP to whoever
// connects to its BMP port, and the sidecar carries that stream to the
// listener over mTLS with the router's SVID. It adds no trust: the listener
// still derives the tenant from the SVID. It reconnects until cleanup.
func bridgeBMP(t *testing.T, routerAddr, listenerAddr string, cfg *tls.Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			pipeBMP(ctx, routerAddr, listenerAddr, cfg)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}()
}

func pipeBMP(ctx context.Context, routerAddr, listenerAddr string, cfg *tls.Config) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", listenerAddr)
	if err != nil {
		return
	}
	listener := tls.Client(upstream, cfg)
	if err := listener.HandshakeContext(ctx); err != nil {
		_ = listener.Close()
		return
	}
	router, err := dialer.DialContext(ctx, "tcp", routerAddr)
	if err != nil {
		_ = listener.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(listener, router); done <- struct{}{} }()
	go func() { _, _ = io.Copy(router, listener); done <- struct{}{} }()
	select {
	case <-ctx.Done():
	case <-done:
	}
	_ = router.Close()
	_ = listener.Close()
}

// --- the routing lab ---

// routingLab is four FRRouting containers on their own docker network.
type routingLab struct {
	name, network string
	ip            map[string]string
}

var labRouters = []string{"edge", "rrc", "rtr-a", "rtr-b"}

func startRoutingLab(t *testing.T) *routingLab {
	t.Helper()
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		testsupport.SkipOrFatal(t, "the BGP receipt runs real BGP speakers in docker: %v %s", err, out)
	}
	lab := &routingLab{name: os.Getenv("PROBECTL_TEST_BGP_LAB_NAME")}
	if lab.name == "" {
		lab.name = "probectl-it-bgp-" + strconv.FormatInt(time.Now().UnixNano()%1e8, 36)
	}
	lab.network = lab.name + "-net"
	var subnet string
	for i := 0; i < 8 && subnet == ""; i++ {
		candidate := fmt.Sprintf("10.231.%d.0/24", (time.Now().Nanosecond()/1000+i*37)%250+1)
		out, err := exec.Command("docker", "network", "create", "--subnet", candidate, lab.network).CombinedOutput()
		if err == nil {
			subnet = candidate
		} else if !strings.Contains(string(out), "overlap") {
			t.Fatalf("docker network create %s: %v %s", lab.network, err, out)
		}
	}
	if subnet == "" {
		t.Fatal("no free 10.231.x.0/24 subnet for the routing lab's network")
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", lab.network).Run() })
	base := strings.TrimSuffix(subnet, "0/24")
	lab.ip = map[string]string{"edge": base + "10", "rrc": base + "20", "rtr-a": base + "31", "rtr-b": base + "32"}
	for _, r := range labRouters {
		lab.startRouter(t, r)
	}
	lab.awaitRoutes(t, "rrc", map[string]string{
		prefixA: path(edgeASN, originA), prefixB: path(edgeASN, originB), prefixDecoy: path(edgeASN, originDecoy),
	})
	lab.awaitRoutes(t, "rtr-a", map[string]string{prefixA: path(edgeASN, originA)})
	lab.awaitRoutes(t, "rtr-b", map[string]string{prefixB: path(edgeASN, originB)})
	t.Logf("[deterministic] routing lab %s up on %s: edge AS%d announces %s, %s and %s; rrc AS%d records MRT; rtr-a AS%d and rtr-b AS%d export BMP",
		lab.name, subnet, edgeASN, prefixA, prefixB, prefixDecoy, rrcASN, rtrAASN, rtrBASN)
	return lab
}

func path(asns ...int) string {
	parts := make([]string, len(asns))
	for i, a := range asns {
		parts[i] = strconv.Itoa(a)
	}
	return strings.Join(parts, " ")
}

func (lab *routingLab) container(router string) string { return lab.name + "-" + router }

func (lab *routingLab) docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (lab *routingLab) startRouter(t *testing.T, router string) {
	t.Helper()
	name := lab.container(router)
	_ = exec.Command("docker", "rm", "-f", name).Run()
	args := []string{"create", "--name", name, "--network", lab.network, "--ip", lab.ip[router],
		"--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN", "--ulimit", "nofile=4096:4096"}
	if strings.HasPrefix(router, "rtr-") {
		args = append(args, "-p", "127.0.0.1::5000") // BMP, on a loopback port docker picks
	}
	lab.docker(t, append(args, frrImage)...)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "25", name).CombinedOutput()
			t.Logf("routing lab %s log tail:\n%s", router, out)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	dir := t.TempDir()
	bmp := ""
	if strings.HasPrefix(router, "rtr-") {
		bmp = " -M bmp"
	}
	files := map[string]string{
		"daemons":    "zebra=yes\nbgpd=yes\nvtysh_enable=yes\nzebra_options=\"-A 127.0.0.1 -s 90000000\"\nbgpd_options=\"-A 127.0.0.1" + bmp + "\"\n",
		"vtysh.conf": "service integrated-vtysh-config\n",
		"frr.conf":   lab.frrConf(router),
	}
	for file, body := range files {
		p := filepath.Join(dir, file)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		lab.docker(t, "cp", p, name+":/etc/frr/"+file)
	}
	lab.docker(t, "start", name)
}

func (lab *routingLab) frrConf(router string) string {
	head := "frr defaults traditional\nhostname " + router + "\n!\n"
	neighbor := func(peer string, asn int) string {
		return fmt.Sprintf(" neighbor %s remote-as %d\n", lab.ip[peer], asn)
	}
	common := " no bgp ebgp-requires-policy\n"
	switch router {
	case "edge":
		return head + fmt.Sprintf(`ip prefix-list TO-A seq 5 permit %s
ip prefix-list TO-B seq 5 permit %s
!
route-map ORIGIN-A permit 10
 set as-path prepend %d
exit
route-map ORIGIN-B permit 10
 set as-path prepend %d
exit
route-map ORIGIN-DECOY permit 10
 set as-path prepend %d
exit
!
router bgp %d
 bgp router-id %s
`, prefixA, prefixB, originA, originB, originDecoy, edgeASN, lab.ip["edge"]) + common +
			" no bgp network import-check\n" + neighbor("rrc", rrcASN) + neighbor("rtr-a", rtrAASN) + neighbor("rtr-b", rtrBASN) +
			fmt.Sprintf(` address-family ipv4 unicast
  network %s route-map ORIGIN-A
  network %s route-map ORIGIN-B
  network %s route-map ORIGIN-DECOY
  neighbor %s prefix-list TO-A out
  neighbor %s prefix-list TO-B out
 exit-address-family
exit
`, prefixA, prefixB, prefixDecoy, lab.ip["rtr-a"], lab.ip["rtr-b"])
	case "rrc":
		return head + "dump bgp updates /var/lib/frr/updates.mrt\n!\n" +
			fmt.Sprintf("router bgp %d\n bgp router-id %s\n", rrcASN, lab.ip["rrc"]) + common + neighbor("edge", edgeASN) + "exit\n"
	default:
		// The BMP monitors docs/bgp.md configures for FRR. Without
		// soft-reconfiguration inbound FRR keeps no pre-policy Adj-RIB-In, so
		// the routes arrive on the post-policy monitor.
		asn := map[string]int{"rtr-a": rtrAASN, "rtr-b": rtrBASN}[router]
		return head + fmt.Sprintf("router bgp %d\n bgp router-id %s\n", asn, lab.ip[router]) + common + neighbor("edge", edgeASN) +
			" bmp targets probectl\n  bmp listener 0.0.0.0 port 5000\n  bmp monitor ipv4 unicast pre-policy\n  bmp monitor ipv4 unicast post-policy\n exit\nexit\n"
	}
}

// routes reads one router's BGP table: prefix -> AS paths.
func (lab *routingLab) routes(t *testing.T, router string) map[string][]string {
	t.Helper()
	out, err := exec.Command("docker", "exec", lab.container(router), "vtysh", "-c", "show bgp ipv4 unicast json").Output()
	if err != nil {
		return nil
	}
	var table struct {
		Routes map[string][]struct {
			Path string `json:"path"`
		} `json:"routes"`
	}
	if json.Unmarshal(out, &table) != nil {
		return nil
	}
	got := map[string][]string{}
	for p, paths := range table.Routes {
		for _, x := range paths {
			got[p] = append(got[p], x.Path)
		}
	}
	return got
}

func (lab *routingLab) awaitRoutes(t *testing.T, router string, want map[string]string) {
	t.Helper()
	shipped.Await(t, fmt.Sprintf("%s to hold %v", router, want), 120*time.Second, func() bool {
		got := lab.routes(t, router)
		if len(got) != len(want) {
			return false
		}
		for p, asPath := range want {
			if !slices.Equal(got[p], []string{asPath}) {
				return false
			}
		}
		return true
	})
}

// inject changes three routes at edge with real BGP UPDATEs: A's prefix is
// hijacked by AS65021, B's prefix leaks through no-transit AS64666 from its
// second origin, and the decoy changes origin.
func (lab *routingLab) inject(t *testing.T) {
	t.Helper()
	lab.docker(t, "exec", lab.container("edge"), "vtysh",
		"-c", "configure terminal",
		"-c", "route-map ORIGIN-A permit 10", "-c", "no set as-path prepend", "-c", fmt.Sprintf("set as-path prepend %d", hijackerA),
		"-c", "route-map ORIGIN-B permit 10", "-c", "no set as-path prepend", "-c", fmt.Sprintf("set as-path prepend %d %d", noTransitB, originB2),
		"-c", "route-map ORIGIN-DECOY permit 10", "-c", "no set as-path prepend", "-c", fmt.Sprintf("set as-path prepend %d", originDecoyTo),
		"-c", "end")
	lab.awaitRoutes(t, "rrc", map[string]string{
		prefixA: path(edgeASN, hijackerA), prefixB: path(edgeASN, noTransitB, originB2), prefixDecoy: path(edgeASN, originDecoyTo),
	})
	lab.awaitRoutes(t, "rtr-a", map[string]string{prefixA: path(edgeASN, hijackerA)})
	lab.awaitRoutes(t, "rtr-b", map[string]string{prefixB: path(edgeASN, noTransitB, originB2)})
	t.Logf("[deterministic] injected at edge: %s hijacked by AS%d; %s leaked via AS%d from AS%d; decoy %s now from AS%d",
		prefixA, hijackerA, prefixB, noTransitB, originB2, prefixDecoy, originDecoyTo)
}

// collectorMRT copies the lab collector's MRT update dump out of its
// container once it holds the injected updates.
func (lab *routingLab) collectorMRT(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "updates.mrt")
	var size int64
	shipped.Await(t, "the lab collector's MRT to stop growing", 30*time.Second, func() bool {
		lab.docker(t, "cp", lab.container("rrc")+":/var/lib/frr/updates.mrt", dst)
		fi, err := os.Stat(dst)
		if err != nil {
			return false
		}
		stable := fi.Size() > 0 && fi.Size() == size
		size = fi.Size()
		if !stable {
			time.Sleep(time.Second)
		}
		return stable
	})
	t.Logf("[deterministic] lab collector MRT: %d bytes of BGP4MP UPDATE records", size)
	return dst
}

// bmpAddr is the loopback address docker published the router's BMP port on.
func (lab *routingLab) bmpAddr(t *testing.T, router string) string {
	t.Helper()
	out := strings.TrimSpace(lab.docker(t, "port", lab.container(router), "5000/tcp"))
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "127.0.0.1:") {
			return line
		}
	}
	t.Fatalf("docker port %s 5000/tcp = %q, want a 127.0.0.1 binding", router, out)
	return ""
}
