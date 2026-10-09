// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// TestTenantExportAndErasureRealStack is the real-stack receipt for F55
// (export, residency and verifiable deletion): the export-then-erase workflow
// a departing tenant gets, through the public API, the CLI and the console,
// across every store, on the shipped control plane and agents.
//
// The stack is the shipped probectl-control (MSP license, least-privilege
// serve login, TLS on every listener) on the dev stack: PostgreSQL, Kafka,
// ClickHouse for every telemetry plane with DB-level tenant scoping and strict
// tenant lanes, Prometheus with its admin API, a filesystem object store, and
// the real IdP. Four tenants: P (pooled), H (hybrid) and S (siloed) are each
// exported and then erased through one surface (API, CLI, console); K is a
// pooled bystander that shares every pooled table with P.
//
//  1. Every store holds each tenant's data, written the way production writes
//     it: control state through the API (a test, a token), OTLP traces and
//     logs through the shipped OTLP/HTTP listener, a path discovery through
//     the API (paths and the topology graph), probe results and failure
//     artifacts from a shipped agent (Prometheus series, object store), and,
//     for H and S, whose lanes are namespaced, NetFlow from a stand-in
//     exporter through the shipped flow agent, a recorded eBPF capture through
//     the shipped eBPF agent, and DEM samples from the shipped endpoint agent.
//  2. Export: P through GET /v1/lifecycle/export, H through `probectl
//     lifecycle export`, S through the console's download link. Each bundle
//     carries every plane that tenant has, counted in the manifest, and none
//     of another tenant's rows.
//  3. Erase: P through POST /v1/lifecycle/erase, H through `probectl
//     lifecycle erase`, S through the console's slug-confirmed dialog. Each
//     attestation is complete, names every store verified zero, recomputes to
//     its report_sha256, and that digest is on the provider audit chain.
//  4. Every store then reads zero for P, H and S, read directly: PostgreSQL
//     rows, ClickHouse rows and per-tenant databases, Prometheus series, object
//     keys. Their collectors keep publishing and, a usage flush later, nothing
//     has refilled. K's data is intact in every store and its export unchanged.
func TestTenantExportAndErasureRealStack(t *testing.T) {
	irPrivate := filepath.Join(t.TempDir(), "ir-private")
	if err := os.Mkdir(irPrivate, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	st := shipped.Start(t, shipped.Options{Name: "f55", TenantBand: 6, Env: map[string]string{
		// Erasure crypto-shreds each tenant's IR attribution key, so the
		// investigation-only private keyring is mounted for it (docs/configuration.md).
		"PROBECTL_IR_PRIVATE_KEY_DIR":    irPrivate,
		"PROBECTL_IR_UNLOCK_KEY_ID":      "f55-ir-unlock",
		"PROBECTL_IR_UNLOCK_KEY":         base64.StdEncoding.EncodeToString(unlock),
		"PROBECTL_BACKUP_RETENTION_DAYS": "14",
	}})
	op := st.OnboardOperator(t, "root@msp-f55.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "<html><body>f55 checkout is down for "+r.URL.Query().Get("for")+"</body></html>")
	}))
	t.Cleanup(page.Close)

	P := &f55Tenant{slug: "f55-pool-" + run, name: "Pooled Erasure", model: "pooled", admin: "ada@acme.example", surface: "API"}
	H := &f55Tenant{slug: "f55-hyb-" + run, name: "Hybrid Erasure", model: "hybrid", admin: "bob@globex.example", surface: "CLI"}
	S := &f55Tenant{slug: "f55-silo-" + run, name: "Siloed Erasure", model: "siloed", admin: "carla@acme.example", surface: "console"}
	K := &f55Tenant{slug: "f55-keep-" + run, name: "Pooled Bystander", model: "pooled", admin: "dan@acme.example"}
	all, erased := []*f55Tenant{P, H, S, K}, []*f55Tenant{P, H, S}

	// 1. Provision, sign in, and write every store the way production does.
	for i, tn := range all {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id, tn.mark, tn.net = row.ID, fmt.Sprintf("f55-%d-%s", i, run), fmt.Sprintf("10.%d.0.", 60+i)
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "test.read", "test.write", "lifecycle.export", "lifecycle.erase")
		var posture struct {
			LaneNamespace struct{ Namespace string } `json:"lane_namespace"`
			SiloRouting   struct {
				ClickHouseDatabase string `json:"clickhouse_database"`
			} `json:"silo_routing"`
		}
		st.MustCLI(t, tn.env(), &posture, "isolation", "status")
		tn.ns, tn.chdb = posture.LaneNamespace.Namespace, posture.SiloRouting.ClickHouseDatabase
		if (tn.model == "pooled") != (tn.chdb == "") || (tn.model == "pooled") != (tn.ns == "") {
			t.Fatalf("tenant %s (%s) routes to database %q, lane %q", tn.slug, tn.model, tn.chdb, tn.ns)
		}
		tn.seed(t, st, page.URL)
	}
	for _, tn := range all {
		tn.awaitStores(t)
	}
	before := map[*f55Tenant]f55Counts{}
	for _, tn := range all {
		before[tn] = tn.counts(t, st)
		t.Logf("tenant %s (%s) before export: %+v", tn.slug, tn.model, before[tn])
	}

	// 2. Export, one surface per erased tenant (and K's, to compare later).
	code, raw := st.Do(t, P.cookie, http.MethodGet, "/v1/lifecycle/export", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/lifecycle/export as %s = %d: %.300s", P.slug, code, raw)
	}
	P.checkBundle(t, "the API export", raw, all)
	stdout, stderr, exit := st.CLI(H.env(), "lifecycle", "export")
	if exit != 0 {
		t.Fatalf("probectl lifecycle export as %s: exit %d: %s", H.slug, exit, stderr)
	}
	H.checkBundle(t, "the CLI export", []byte(stdout), all)
	download := filepath.Join(t.TempDir(), "console-export.tar.gz")
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/admin",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: S.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Data lifecycle"},
		Steps:  []testsupport.RenderStep{{Click: "Export my data (tar.gz)", Role: "link", Download: download}},
	})
	consoleBundle, err := os.ReadFile(download)
	if err != nil {
		t.Fatalf("the console's export download: %v", err)
	}
	S.checkBundle(t, "the console export", consoleBundle, all)
	_, keepBefore := K.export(t, st)

	// 3. Erase, one surface per tenant. As the runbook says, a tenant's agents
	// stop first: a browser agent writes its artifacts straight to the object
	// store, where no fence can refuse them. Its collectors keep publishing
	// through the bus, where the erase's fence must refuse them.
	st.Stop(t, P.agentLabel())
	code, raw = st.Do(t, P.cookie, http.MethodPost, "/v1/lifecycle/erase", map[string]string{"confirm": P.slug})
	if code != http.StatusOK {
		t.Fatalf("POST /v1/lifecycle/erase as %s = %d: %.500s", P.slug, code, raw)
	}
	P.checkAttestation(t, raw)
	st.Stop(t, H.agentLabel())
	stdout, stderr, exit = st.CLI(H.env(), "lifecycle", "erase", "--body", fmt.Sprintf(`{"confirm":%q}`, H.slug))
	if exit != 0 {
		t.Fatalf("probectl lifecycle erase as %s: exit %d: %s", H.slug, exit, stderr)
	}
	H.checkAttestation(t, []byte(stdout))
	st.Stop(t, S.agentLabel())
	kept := filepath.Join(t.TempDir(), "console-receipt.json")
	receipt := testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/admin",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: S.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Data lifecycle"},
		Steps: []testsupport.RenderStep{
			{Click: "Erase tenant data", Expect: []string{"Tenant slug confirmation"}},
			{Fill: `[role="dialog"] input`, Value: S.slug},
			{Click: "Erase tenant data", Within: `[role="dialog"]`, Expect: []string{"Erasure receipt", "complete", "Report SHA-256"}},
			{Click: "Download receipt (JSON)", Role: "link", Download: kept},
		},
	})
	raw, err = os.ReadFile(kept)
	if err != nil {
		t.Fatalf("the console's erasure receipt download: %v", err)
	}
	S.checkAttestation(t, raw)
	for _, e := range receipt.Errors {
		if strings.Contains(e, "HTTP 5") {
			t.Errorf("the console erase hit a server error: %s", e)
		}
	}

	// The provider audit chain holds each attestation's digest.
	var chain struct {
		Items []struct {
			Target string
			Data   map[string]any
		}
	}
	st.MustCLI(t, opEnv, &chain, "provider", "audit", "--query", "action=lifecycle.erase")
	onChain := map[string]map[string]any{}
	for _, ev := range chain.Items {
		onChain[ev.Target] = ev.Data
	}
	for _, tn := range erased {
		data := onChain[tn.id]
		if data == nil || data["report_sha256"] != tn.sha || data["complete"] != true {
			t.Errorf("the provider audit chain's lifecycle.erase for %s = %v, want complete with report_sha256 %s", tn.slug, data, tn.sha)
		}
	}

	// 4. Every store reads zero for the erased tenants, and stays zero while
	// their collectors keep publishing; K is untouched. The MSP usage recorder
	// flushes counts once a minute and the fairness series go out every 30
	// seconds, so wait until K's usage has been flushed after the last erasure:
	// a count buffered for an erased tenant would have been written back too.
	erasedAt := dbNow(t, st)
	shipped.Await(t, "a usage flush after the erasures", 150*time.Second, func() bool {
		return usageFlushedSince(t, st, K.id, erasedAt)
	})
	for _, tn := range erased {
		if got := tn.counts(t, st); !got.zero() {
			t.Errorf("tenant %s (%s, erased through the %s) still holds data: %+v", tn.slug, tn.model, tn.surface, got)
		}
		if code, _ := st.Do(t, tn.cookie, http.MethodGet, "/v1/me", nil); code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Errorf("tenant %s's admin session still answers /v1/me after erasure: %d", tn.slug, code)
		}
	}
	after := K.counts(t, st)
	if !after.covers(before[K]) {
		t.Errorf("the bystander lost data to the erasures: before %+v, after %+v", before[K], after)
	}
	_, keepAfter := K.export(t, st)
	for _, plane := range []string{"otel_spans", "otel_logs", "path_hops", "path_links", "topology"} {
		if keepAfter[plane] != keepBefore[plane] || (plane != "path_links" && keepAfter[plane] == 0) {
			t.Errorf("the bystander's export %s: %v rows before the erasures, %v after", plane, keepBefore[plane], keepAfter[plane])
		}
	}
}

func (tn *f55Tenant) agentLabel() string { return "agent-f55-agent-" + tn.id[:8] }

// retainedByDesign are the provider-global integrity tables that outlive a
// tenant erase on purpose (docs/runbooks/tenant-offboarding.md, step 3;
// internal/tenancy/tables.go): sequence numbers and hashes, never telemetry.
var retainedByDesign = map[string]bool{
	`"public"."audit_stream_heads"`:   true,
	`"public"."ir_key_shred_heads"`:   true,
	`"public"."ir_key_shred_records"`: true,
}

// f55Tenant is one tenant of the receipt and what it seeded.
type f55Tenant struct {
	slug, name, model, admin, surface string
	id, mark, cookie, token, ns, chdb string
	testID, agent, net                string // net: the tenant's own workload addresses
	sha                               string
}

func (tn *f55Tenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

// collectors: the flow, eBPF and endpoint planes publish straight to the bus,
// which strict tenant lanes allow only on a namespaced (hybrid/siloed) lane.
func (tn *f55Tenant) collectors() bool { return tn.ns != "" }

func (tn *f55Tenant) table(name string) string {
	if tn.chdb != "" {
		return tn.chdb + "." + name
	}
	return "default." + name
}

func (tn *f55Tenant) seed(t *testing.T, st *shipped.Stack, pageURL string) {
	t.Helper()
	// Control state: a test, through the API.
	code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": "checkout " + tn.mark, "type": "icmp", "target": "127.0.0.1", "interval_seconds": 60,
		"timeout_seconds": 5, "params": map[string]string{"allow_private_targets": "true"}, "enabled": false,
	})
	var test struct{ ID string }
	if code != http.StatusCreated || json.Unmarshal(raw, &test) != nil || test.ID == "" {
		t.Fatalf("create a test as %s = %d: %s", tn.slug, code, raw)
	}
	tn.testID = test.ID
	// Paths and the topology graph: a discovery through the API.
	if code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/tests/"+tn.testID+"/path", nil); code != http.StatusOK {
		t.Fatalf("discover the test's path as %s = %d: %s", tn.slug, code, raw)
	}
	// OTLP traces and logs through the shipped OTLP/HTTP listener.
	code, raw = st.Do(t, tn.cookie, http.MethodPost, "/v1/otlp-tokens", map[string]string{"name": "f55-collector"})
	var otlp struct{ Token string }
	if code != http.StatusCreated || json.Unmarshal(raw, &otlp) != nil || otlp.Token == "" {
		t.Fatalf("mint an OTLP token as %s = %d: %s", tn.slug, code, raw)
	}
	postOTLP(t, st, otlp.Token, tn.mark)
	// Probe results (Prometheus) and failure artifacts (object store) from a
	// shipped agent running a browser canary against a page that is down.
	tn.agent = uuid.NewString()
	dir := st.EnrollAgent(t, tn.id, tn.agent, "f55-agent-"+tn.id[:8])
	declared := ""
	if tn.model != "pooled" {
		declared = "\n  isolation: " + tn.model
	}
	st.StartAgent(t, dir, "f55-agent-"+tn.id[:8], []string{"browser"}, fmt.Sprintf(`artifact_store:
  dir: %q%s
browser:
  driver: http
canaries:
  - type: browser
    target: %q
    interval: 2s
    timeout: 5s
    params:
      allow_private_targets: "true"
`, st.ObjectDir, declared, pageURL+"/checkout?for="+tn.mark))
	if !tn.collectors() {
		return
	}
	brokers := `["` + strings.Join(testsupport.KafkaBrokers(), `","`) + `"]`
	bus := fmt.Sprintf("bus:\n  mode: kafka\n  brokers: %s\n  namespace: %q\n", brokers, tn.ns)
	// NetFlow v5 from a stand-in exporter through the shipped flow agent.
	udp := shipped.FreeUDPAddr(t)
	st.StartCollector(t, "probectl-flow-agent", "f55-flow-"+tn.id[:8], "PROBECTL_FLOW", fmt.Sprintf(`apiVersion: probectl.io/flow-agent/v1
tenant_id: %q
agent_id: %q
%snetflow:
  enabled: true
  listen: %q
  allowed_sources: ["127.0.0.1/32"]
ipfix:
  enabled: false
sflow:
  enabled: false
batch_size: 10
flush_interval: 1s
`, tn.id, tn.agent, bus, udp))
	go shipped.ExportNetFlow(t.Context(), udp)
	// A recorded eBPF capture through the shipped eBPF agent (no kernel).
	fixture := filepath.Join(t.TempDir(), "flows.json")
	var flows []map[string]any
	for i := 0; i < 3; i++ {
		flows = append(flows, map[string]any{
			"tenant_id": tn.id, "agent_id": tn.agent, "host": tn.mark, "source_address": tn.net + strconv.Itoa(5+i),
			"source_port": 51000 + i, "source_pid": 4242, "destination_address": "10.2.0.9", "destination_port": 5432,
			"network_transport": "tcp", "network_type": "ipv4", "bytes": 2048, "packets": 12, "direction": "egress", "state": "established",
		})
	}
	writeJSON(t, fixture, flows)
	st.StartCollector(t, "probectl-ebpf-agent", "f55-ebpf-"+tn.id[:8], "PROBECTL_EBPF", fmt.Sprintf(`apiVersion: probectl.io/ebpf-agent/v1
tenant_id: %q
agent_id: %q
host: %q
%sfixture_path: %q
flush_interval: 1s
health_state_dir: %q
`, tn.id, tn.agent, tn.mark, bus, fixture, t.TempDir()))
	// DEM samples from the shipped endpoint agent, timing the local page.
	st.StartCollector(t, "probectl-endpoint", "f55-endpoint-"+tn.id[:8], "PROBECTL_ENDPOINT", fmt.Sprintf(`apiVersion: probectl.io/endpoint/v1
tenant_id: %q
agent_id: %q
%sinterval: 2s
targets: [%q]
max_hops: 2
probes: 1
session_timeout: 5s
`, tn.id, tn.agent, bus, pageURL+"/?for="+tn.mark))
}

// awaitStores waits until every store the tenant writes holds its data.
func (tn *f55Tenant) awaitStores(t *testing.T) {
	t.Helper()
	planes := map[string]string{
		"OTLP spans": "probectl_otel_spans", "OTLP logs": "probectl_otel_logs", "path hops": "probectl_path_hops2",
	}
	if tn.collectors() {
		planes["flows"], planes["eBPF edges"], planes["endpoint events"] = "probectl_flows", "probectl_ebpf_edges", "probectl_endpoint_events"
	}
	for plane, table := range planes {
		shipped.Await(t, tn.slug+"'s "+plane+" in "+tn.table(table), 90*time.Second, func() bool {
			return chCount(t, fmt.Sprintf(`SELECT count() FROM %s WHERE tenant_id = '%s'`, tn.table(table), tn.id)) > 0
		})
	}
	shipped.Await(t, tn.slug+"'s probe series in Prometheus", 90*time.Second, func() bool {
		return promSeries(t, tn.id) > 0
	})
}

// f55Counts is one tenant's footprint in each store, read directly.
type f55Counts struct {
	Postgres   map[string]int // table -> rows
	ClickHouse map[string]int // table -> rows
	Databases  int            // the tenant's own ClickHouse database (0 or 1)
	Series     int
	Objects    int
}

func (c f55Counts) zero() bool {
	for _, n := range c.Postgres {
		if n != 0 {
			return false
		}
	}
	for _, n := range c.ClickHouse {
		if n != 0 {
			return false
		}
	}
	return c.Databases == 0 && c.Series == 0 && c.Objects == 0
}

// covers reports whether every store still holds at least what it held.
func (c f55Counts) covers(was f55Counts) bool {
	for table, n := range was.Postgres {
		if c.Postgres[table] < n {
			return false
		}
	}
	for table, n := range was.ClickHouse {
		if c.ClickHouse[table] < n {
			return false
		}
	}
	return c.Databases >= was.Databases && c.Series >= was.Series && c.Objects >= was.Objects
}

func (tn *f55Tenant) counts(t *testing.T, st *shipped.Stack) f55Counts {
	t.Helper()
	c := f55Counts{Postgres: pgTenantRows(t, st, tn.id), ClickHouse: map[string]int{}}
	tables := chColumn(t, `SELECT database || '.' || table FROM system.columns WHERE name = 'tenant_id' AND database = 'default'`)
	if tn.chdb != "" && chColumn(t, `SELECT name FROM system.databases`)[tn.chdb] {
		c.Databases = 1
		for table := range chColumn(t, fmt.Sprintf(`SELECT database || '.' || table FROM system.columns WHERE name = 'tenant_id' AND database = '%s'`, tn.chdb)) {
			tables[table] = true
		}
	}
	for table := range tables {
		if n := chCount(t, fmt.Sprintf(`SELECT count() FROM %s WHERE tenant_id = '%s'`, table, tn.id)); n != 0 {
			c.ClickHouse[table] = n
		}
	}
	c.Series = promSeries(t, tn.id)
	for _, prefix := range []string{"tenant", "silo"} {
		_ = filepath.WalkDir(filepath.Join(st.ObjectDir, prefix, tn.id), func(_ string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				c.Objects++
			}
			return nil
		})
	}
	return c
}

// checkBundle reads a portability bundle and requires every plane the tenant
// wrote, counted in the manifest, and nothing of any other tenant.
func (tn *f55Tenant) checkBundle(t *testing.T, how string, raw []byte, all []*f55Tenant) {
	t.Helper()
	files := untar(t, raw)
	var man map[string]any
	if err := json.Unmarshal([]byte(files["manifest.json"]), &man); err != nil {
		t.Fatalf("%s for %s has no readable manifest (files %v): %v", how, tn.slug, slices.Sorted(maps.Keys(files)), err)
	}
	if man["tenant_id"] != tn.id {
		t.Errorf("%s for %s is the manifest of tenant %v", how, tn.slug, man["tenant_id"])
	}
	want := map[string]string{ // bundle file -> text it must hold
		"postgres/tests.jsonl": tn.testID, "otel_spans.jsonl": tn.mark, "otel_logs.jsonl": tn.mark,
		"path_hops.jsonl": "127.0.0.1", "topology.jsonl": "127.0.0.1",
	}
	planes := []string{"otel_spans", "otel_logs", "path_hops", "topology"}
	if tn.collectors() {
		want["flows.jsonl"], want["ebpf_edges.jsonl"], want["endpoint_events.jsonl"] = "10.55.", tn.net, tn.agent
		planes = append(planes, "flows", "ebpf_edges", "endpoint_events")
	}
	for file, text := range want {
		if !strings.Contains(files[file], text) {
			t.Errorf("%s for %s: %s does not hold %q:\n%.400s", how, tn.slug, file, text, files[file])
		}
	}
	for _, plane := range planes {
		if n, _ := man[plane].(float64); n < 1 || int(n) != strings.Count(files[plane+".jsonl"], "\n") {
			t.Errorf("%s for %s: manifest %s = %v for %d lines", how, tn.slug, plane, man[plane], strings.Count(files[plane+".jsonl"], "\n"))
		}
	}
	objects, _ := man["objects"].([]any)
	if len(objects) == 0 {
		t.Errorf("%s for %s inventories no object-store artifact", how, tn.slug)
	}
	for _, other := range all {
		if other == tn {
			continue
		}
		for file, body := range files {
			for _, leak := range []string{other.id, other.mark, other.testID} {
				if strings.Contains(body, leak) {
					t.Errorf("%s for %s: %s holds tenant %s's %q", how, tn.slug, file, other.slug, leak)
				}
			}
		}
	}
}

// checkAttestation requires a complete deletion report naming every store
// verified zero, whose report_sha256 recomputes from the report itself.
func (tn *f55Tenant) checkAttestation(t *testing.T, raw []byte) {
	t.Helper()
	var att tenantlife.Attestation
	if err := json.Unmarshal(raw, &att); err != nil {
		t.Fatalf("the attestation for %s: %v: %s", tn.slug, err, raw)
	}
	tn.sha = att.ReportSHA256
	stores := map[string]tenantlife.StoreResult{}
	for _, s := range att.Stores {
		stores[s.Store] = s
	}
	if !att.Complete || att.TenantID != tn.id || att.BackupRetentionDays != 14 || att.BackupErasureDeadline == nil {
		t.Errorf("the attestation for %s (%s) = %s", tn.slug, tn.surface, raw)
	}
	for _, store := range []string{"postgres", "flows", "endpoint_events", "otel", "ebpf", "paths", "topology", "tsdb", "objects", "tenant_keys", "provider_rows", "tenant_registry"} {
		if s, ok := stores[store]; !ok || !s.VerifiedZero {
			t.Errorf("the attestation for %s: store %s = %+v (present %v), want verified zero", tn.slug, store, s, ok)
		}
	}
	recomputed := att
	recomputed.ReportSHA256 = ""
	canonical, err := json.Marshal(recomputed)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(crypto.Hash(canonical)); got != att.ReportSHA256 {
		t.Errorf("the attestation for %s recomputes to %s, it states %s", tn.slug, got, att.ReportSHA256)
	}
}

// export downloads the tenant's bundle through the API and returns its files
// and the manifest's per-plane counts.
func (tn *f55Tenant) export(t *testing.T, st *shipped.Stack) (map[string]string, map[string]float64) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodGet, "/v1/lifecycle/export", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/lifecycle/export as %s = %d: %.300s", tn.slug, code, raw)
	}
	files := untar(t, raw)
	var man map[string]any
	if err := json.Unmarshal([]byte(files["manifest.json"]), &man); err != nil {
		t.Fatal(err)
	}
	counts := map[string]float64{}
	for k, v := range man {
		if n, ok := v.(float64); ok {
			counts[k] = n
		}
	}
	return files, counts
}

// dbNow is the database's clock, which stamps usage flushes.
func dbNow(t *testing.T, st *shipped.Stack) time.Time {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var now time.Time
	if err := pool.QueryRow(context.Background(), `SELECT now()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now
}

// usageFlushedSince reports whether the usage recorder has written a count for
// tenant since the given database time.
func usageFlushedSince(t *testing.T, st *shipped.Stack, tenant string, since time.Time) bool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM usage_records WHERE tenant_id = $1::uuid AND updated_at > $2`, tenant, since).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// pgTenantRows counts the tenant's rows in every PostgreSQL table that has a
// tenant_id column, in every schema (a siloed tenant's own schema included),
// read as the privileged login.
func pgTenantRows(t *testing.T, st *shipped.Stack, tenant string) map[string]int {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	rows, err := pool.Query(ctx, `
		SELECT n.nspname, c.relname
		  FROM pg_catalog.pg_class c
		  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
		 WHERE c.relkind IN ('r', 'p') AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped
		   AND n.nspname NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var schema, table string
		if err := rows.Scan(&schema, &table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, pgx.Identifier{schema, table}.Sanitize())
	}
	rows.Close()
	out := map[string]int{}
	for _, table := range tables {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id::text = $1`, tenant).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 && !retainedByDesign[table] {
			out[table] = n
		}
	}
	return out
}

func postOTLP(t *testing.T, st *shipped.Stack, token, service string) {
	t.Helper()
	traceID, err := crypto.Random(16)
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := crypto.Random(8)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixNano())
	resource := &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
		Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: service}},
	}}}
	traces, err := proto.Marshal(&coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: resource,
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			TraceId: traceID, SpanId: spanID, Name: "checkout", Kind: tracepb.Span_SPAN_KIND_SERVER,
			StartTimeUnixNano: now - uint64(time.Millisecond), EndTimeUnixNano: now,
		}}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	logs, err := proto.Marshal(&collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: resource,
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
			TimeUnixNano: now, SeverityText: "INFO", SeverityNumber: logspb.SeverityNumber_SEVERITY_NUMBER_INFO,
			Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "payment captured for " + service}},
		}}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for signal, payload := range map[string][]byte{"traces": traces, "logs": logs} {
		req, err := http.NewRequest(http.MethodPost, st.OTLPURL+"/v1/"+signal, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := st.Client().Do(req)
		if err != nil {
			t.Fatalf("POST %s/v1/%s: %v", st.OTLPURL, signal, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("OTLP/HTTP %s export = %d: %s", signal, resp.StatusCode, body)
		}
	}
}

func promSeries(t *testing.T, tenant string) int {
	t.Helper()
	u := strings.TrimRight(os.Getenv("PROBECTL_PROM_URL"), "/") + "/api/v1/query?query=" + url.QueryEscape(`count({tenant_id="`+tenant+`"})`)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("query Prometheus: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode the Prometheus answer: %v", err)
	}
	if len(out.Data.Result) == 0 || len(out.Data.Result[0].Value) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(fmt.Sprint(out.Data.Result[0].Value[1]))
	return n
}

func chColumn(t *testing.T, query string) map[string]bool {
	t.Helper()
	body, err := shipped.CHQuery(shipped.CHURL(), query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line != "" {
			out[line] = true
		}
	}
	return out
}

func chCount(t *testing.T, query string) int {
	t.Helper()
	body, err := shipped.CHQuery(shipped.CHURL(), query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(body))
	if err != nil {
		t.Fatalf("%s returned %q", query, body)
	}
	return n
}

func untar(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the bundle is not gzip: %v (%d bytes)", err, len(raw))
	}
	tr := tar.NewReader(gz)
	files := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatalf("read the bundle: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[hdr.Name] = string(body)
	}
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
