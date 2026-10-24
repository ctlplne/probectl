// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/ee/silo"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// TestTenantQuarantineRealStack is the real-stack receipt for D-62 (per-tenant
// quarantine): with PROBECTL_SILO_FAILURE_MODE=quarantine, a siloed tenant
// whose residency plane is unreachable at boot is quarantined — refused on
// every path with an actionable error — while every other tenant starts and
// runs; the quarantine is audited, metered, alerted and listed for the
// operator; and it is released by itself, with no restart, once the plane is
// back.
//
// The stack is the shipped control plane (probectl-control serve built from
// this tree) on real PostgreSQL, ClickHouse, Kafka and Prometheus, with the
// real IdP. Two residency planes, eu and us, are the dev ClickHouse reached
// through two TCP relays in this test, each its own origin with its own
// pinned reader credential, so "eu is down" is a real connection refusal of
// one plane while the other stays up. Tenants: X siloed on eu, Y siloed on
// us, P pooled.
//
//  1. Provision X, Y and P; each admin signs in through the IdP; each tenant
//     ships an OTLP span that lands in its own database (X's and Y's on their
//     planes).
//  2. Stop mode, for contrast (the alpha default): with eu down the control
//     plane refuses to start for every tenant, naming X.
//  3. Quarantine mode with eu still down: the control plane starts. X is
//     refused on the API (503 tenant_quarantined naming the plane, no
//     operator-side detail), the CLI, OTLP ingest (retryable 503), and a
//     one-shot command (bootstrap-admin). Y and P read and ingest normally.
//     The provider stream records tenant.quarantine_entered; /metrics shows
//     probectl_tenant_quarantined{reason="residency_plane_unreachable"} 1; the
//     provider API, CLI and rendered console list X with the cause and fix.
//  4. eu comes back: within the recheck interval X is released without a
//     restart — its pre-quarantine span reads back, it ingests again, the
//     metric and the provider view clear, and both transitions are on X's own
//     audit chain and the provider stream.
func TestTenantQuarantineRealStack(t *testing.T) {
	chURL, err := url.Parse(shipped.CHURL())
	if err != nil || chURL.Host == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_CLICKHOUSE_URL / PROBECTL_FLOWSTORE_URL must name the dev ClickHouse")
	}
	eu, us := newPlaneRelay(t, chURL.Host), newPlaneRelay(t, chURL.Host)
	plane := func(r *planeRelay) string {
		u := *chURL
		u.Host, u.Path, u.User = r.addr, "", nil
		return u.String()
	}
	const scrape = "d62-quarantine-scrape-ci-only"
	st := shipped.Start(t, shipped.Options{
		Name: "d62", TenantBand: 5,
		DataPlanes: map[string]string{"eu": plane(eu), "us": plane(us)},
		Env: map[string]string{
			"PROBECTL_SILO_FAILURE_MODE":                "quarantine",
			"PROBECTL_SILO_QUARANTINE_RECHECK_INTERVAL": "5s",
			"PROBECTL_METRICS_SCRAPE_TOKEN":             scrape,
		},
	})
	op := st.OnboardOperator(t, "root@msp-d62.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	slugX, slugY, slugP := "d62-eu-"+run, "d62-us-"+run, "d62-pool-"+run

	// 1. Three tenants, each with telemetry in its own database.
	X := provisionResident(t, st, opEnv, slugX, "Eurozone Industries", "eu")
	Y := provisionResident(t, st, opEnv, slugY, "Unity Holdings", "us")
	P := provisionThroughAPI(t, st, op, slugP, "Pooled Partners", "pooled")
	scopes := []string{"tenant.read", "test.read", "metrics.read", "metrics.write", "audit.read"}
	cookies, tokens, otlp := map[string]string{}, map[string]string{}, map[string]string{}
	for tenant, who := range map[string][2]string{
		// Dex's static users (scripts/ci_dex.sh).
		X: {"ada@acme.example", "Eurozone Industries"}, Y: {"bob@globex.example", "Unity Holdings"},
		P: {"carla@acme.example", "Pooled Partners"},
	} {
		cookies[tenant] = st.SignIn(t, tenant, who[0], who[1])
		tokens[tenant] = st.APIToken(t, cookies[tenant], scopes...)
		otlp[tenant] = otlpToken(t, st, cookies[tenant])
	}
	before := map[string]string{X: "d62-x-before-" + run, Y: "d62-y-before-" + run, P: "d62-p-before-" + run}
	for tenant, service := range before {
		if code := postSpan(t, st, otlp[tenant], service); code != http.StatusOK {
			t.Fatalf("tenant %s OTLP export before the fault = %d", tenant, code)
		}
	}
	for tenant, service := range before {
		awaitTrace(t, st, tokens[tenant], service)
	}
	if n := chCount(t, fmt.Sprintf(`SELECT count() FROM %s.probectl_otel_spans WHERE service = '%s'`, silo.CHDatabase(X), before[X])); n == 0 {
		t.Fatalf("X's span is not in its own database %s", silo.CHDatabase(X))
	}

	// 2. Stop mode (the alpha default) with eu down: nobody starts.
	eu.down()
	refused := st.ServeUntilExit(t, "control-stop", map[string]string{"PROBECTL_SILO_FAILURE_MODE": "stop"}, 120*time.Second)
	if !strings.Contains(refused, "silo reader-scope catch-up before routing") || !strings.Contains(refused, X) {
		t.Fatalf("stop mode with eu down did not refuse startup naming %s:\n%s", X, lastLines(refused, 30))
	}
	t.Logf("RECEIPT stop mode, eu down, refused startup:\n%s", lastLines(refused, 2))

	// 3. Quarantine mode, eu still down: everyone but X starts.
	st.RestartControl(t, "control-quarantine", nil)
	code, body := st.Do(t, cookies[X], http.MethodGet, "/v1/otlp/traces?service="+before[X], nil)
	assertQuarantined(t, "X's session read of its traces", code, body)
	t.Logf("RECEIPT X API (session) GET /v1/otlp/traces = %d %s", code, body)
	stdout, stderr, exit := st.CLI(map[string]string{"PROBECTL_API_TOKEN": tokens[X]}, "isolation", "status")
	if exit == 0 || !strings.Contains(stdout+stderr, "tenant_quarantined") || !strings.Contains(stdout+stderr, `"eu" is unreachable`) {
		t.Fatalf("`probectl isolation status` as X = exit %d: %s%s; want the actionable quarantine refusal", exit, stdout, stderr)
	}
	t.Logf("RECEIPT X CLI `probectl isolation status` = exit %d: %s%s", exit, strings.TrimSpace(stdout), strings.TrimSpace(stderr))
	if code := postSpan(t, st, otlp[X], "d62-x-during-"+run); code != http.StatusServiceUnavailable {
		t.Fatalf("X's OTLP export during the quarantine = %d, want a retryable 503", code)
	}
	if out, err := st.TrySubcommand("bootstrap-admin", "-tenant", X, "-email", "late@acme.example"); err == nil || !strings.Contains(out, "quarantined") {
		t.Fatalf("bootstrap-admin for the quarantined tenant = %v:\n%s; want the quarantine refusal", err, out)
	} else {
		t.Logf("RECEIPT X one-shot bootstrap-admin refused: %v: %s", err, lastLines(out, 1))
	}
	st.Subcommand(t, "bootstrap-admin", "-tenant", Y, "-email", "late@globex.example")
	during := map[string]string{Y: "d62-y-during-" + run, P: "d62-p-during-" + run}
	for tenant, service := range during {
		if code := postSpan(t, st, otlp[tenant], service); code != http.StatusOK {
			t.Fatalf("tenant %s OTLP export during X's quarantine = %d", tenant, code)
		}
	}
	for tenant, service := range during {
		awaitTrace(t, st, tokens[tenant], service)
		awaitTrace(t, st, tokens[tenant], before[tenant])
		status := isolationStatus(t, st, tokens[tenant])
		if tenant == Y && status.SiloRouting.ClickHouseDatabase != silo.CHDatabase(Y) {
			t.Errorf("Y's isolation status during X's quarantine = %+v", status)
		}
	}

	// Audited, metered, listed.
	if !providerAudited(t, st, opEnv, silo.AuditTenantQuarantined, X) {
		t.Errorf("the provider stream has no %s for %s", silo.AuditTenantQuarantined, X)
	}
	shipped.Await(t, "probectl_tenant_quarantined{reason=residency_plane_unreachable} 1", 30*time.Second, func() bool {
		return metricValue(t, st, scrape, `probectl_tenant_quarantined{reason="residency_plane_unreachable"}`) == 1
	})
	t.Logf("RECEIPT /metrics: probectl_tenant_quarantined{reason=\"residency_plane_unreachable\"} = %v", metricValue(t, st, scrape, `probectl_tenant_quarantined{reason="residency_plane_unreachable"}`))
	view := quarantineView(t, st, opEnv)
	t.Logf("RECEIPT provider view during quarantine: %+v", view)
	if len(view) != 1 || view[0].TenantID != X || view[0].Slug != slugX || view[0].Reason != "residency_plane_unreachable" ||
		view[0].Plane != "eu" || view[0].Detail == "" || !strings.Contains(view[0].Remedy, "restore connectivity") || view[0].Stale {
		t.Fatalf("`probectl provider quarantine` = %+v, want only X with the cause and the fix", view)
	}
	console := testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/provider",
		Cookies:        []testsupport.RenderCookie{{Name: auth.ProviderSessionCookie, Value: op}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Quarantined tenants", slugX, "Residency plane unreachable", "restore connectivity"},
	})
	for _, e := range console.Errors {
		if strings.Contains(e, "HTTP 5") {
			t.Errorf("the provider console hit a server error: %s", e)
		}
	}

	// 4. eu is back: X is released by the supervisor, no restart.
	eu.up(t)
	shipped.Await(t, "X released from quarantine", 60*time.Second, func() bool {
		_, _, exit := st.CLI(map[string]string{"PROBECTL_API_TOKEN": tokens[X]}, "isolation", "status")
		return exit == 0
	})
	awaitTrace(t, st, tokens[X], before[X])
	after := "d62-x-after-" + run
	shipped.Await(t, "X's OTLP export accepted again", 30*time.Second, func() bool {
		return postSpan(t, st, otlp[X], after) == http.StatusOK
	})
	awaitTrace(t, st, tokens[X], after)
	if got := isolationStatus(t, st, tokens[X]); got.SiloRouting.ClickHouseDatabase != silo.CHDatabase(X) {
		t.Errorf("X's isolation status after release = %+v", got)
	}
	shipped.Await(t, "the quarantine metric clears", 30*time.Second, func() bool {
		return metricValue(t, st, scrape, `probectl_tenant_quarantined{reason="residency_plane_unreachable"}`) == 0
	})
	shipped.Await(t, "the provider view clears", 30*time.Second, func() bool { return len(quarantineView(t, st, opEnv)) == 0 })
	// DPR-381: one transition each, however many processes held it.
	if n := providerAuditCount(t, st, opEnv, silo.AuditTenantQuarantined, X); n != 1 {
		t.Errorf("the provider stream has %d %s events for %s, want exactly 1", n, silo.AuditTenantQuarantined, X)
	}
	if n := providerAuditCount(t, st, opEnv, silo.AuditTenantReleased, X); n != 1 {
		t.Errorf("the provider stream has %d %s events for %s, want exactly 1", n, silo.AuditTenantReleased, X)
	}
	var chain struct {
		Items []struct{ Action, Actor string }
	}
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": tokens[X]}, &chain, "audit", "list")
	onChain := map[string]bool{}
	for _, ev := range chain.Items {
		if ev.Actor == silo.QuarantineActor {
			onChain[ev.Action] = true
		}
	}
	if !onChain[silo.AuditTenantQuarantined] || !onChain[silo.AuditTenantReleased] {
		t.Errorf("X's own audit chain lacks the quarantine transitions: %+v", chain.Items)
	}
	t.Logf("RECEIPT X released without a restart; X's own chain carries %v; provider view now %d rows", onChain, len(quarantineView(t, st, opEnv)))
	st.Subcommand(t, "bootstrap-admin", "-tenant", X, "-email", "late@acme.example")
	if raw, err := os.ReadFile(st.Log); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "silo quarantine") || strings.Contains(line, "D-62 quarantine mode") {
				t.Logf("RECEIPT control log: %s", line)
			}
		}
	}
}

func assertQuarantined(t *testing.T, what string, code int, body []byte) {
	t.Helper()
	var envelope struct {
		Error struct{ Code, Message string }
	}
	_ = json.Unmarshal(body, &envelope)
	if code != http.StatusServiceUnavailable || envelope.Error.Code != "tenant_quarantined" ||
		!strings.Contains(envelope.Error.Message, `"eu" is unreachable`) || !strings.Contains(envelope.Error.Message, "operator") ||
		strings.Contains(envelope.Error.Message, "PROBECTL_") {
		t.Fatalf("%s = %d %s; want 503 tenant_quarantined naming the plane", what, code, body)
	}
	if strings.Contains(string(body), "connection refused") || strings.Contains(string(body), "127.0.0.1") {
		t.Fatalf("%s leaked the operator-side cause to the tenant: %s", what, body)
	}
}

func provisionResident(t *testing.T, st *shipped.Stack, opEnv map[string]string, slug, name, residency string) string {
	t.Helper()
	var row tenantRow
	st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
		fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"siloed","residency":%q}`, slug, name, residency))
	if row.ID == "" || row.IsolationModel != "siloed" {
		t.Fatalf("provision %s on %s = %+v", slug, residency, row)
	}
	return row.ID
}

func awaitTrace(t *testing.T, st *shipped.Stack, token, service string) {
	t.Helper()
	shipped.Await(t, "trace "+service+" readable by its tenant", 60*time.Second, func() bool {
		return traceServices(t, st, token, service)
	})
}

// postSpan sends one span over OTLP/HTTP and returns the status.
func postSpan(t *testing.T, st *shipped.Stack, token, service string) int {
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
	payload, err := proto.Marshal(&coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
			Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: service}},
		}}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			TraceId: traceID, SpanId: spanID, Name: "quarantine " + hex.EncodeToString(spanID[:4]),
			Kind: tracepb.Span_SPAN_KIND_SERVER, StartTimeUnixNano: now - uint64(time.Millisecond), EndTimeUnixNano: now,
		}}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, st.OTLPURL+"/v1/traces", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := st.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s/v1/traces: %v", st.OTLPURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

type quarantineItem struct {
	TenantID string `json:"tenant_id"`
	Slug     string `json:"slug"`
	Reason   string `json:"reason"`
	Plane    string `json:"plane"`
	Detail   string `json:"detail"`
	Remedy   string `json:"remedy"`
	Replica  string `json:"replica"`
	Stale    bool   `json:"stale"`
}

func quarantineView(t *testing.T, st *shipped.Stack, opEnv map[string]string) []quarantineItem {
	t.Helper()
	var out struct{ Items []quarantineItem }
	st.MustCLI(t, opEnv, &out, "provider", "quarantine")
	return out.Items
}

func providerAudited(t *testing.T, st *shipped.Stack, opEnv map[string]string, action, target string) bool {
	t.Helper()
	return providerAuditCount(t, st, opEnv, action, target) > 0
}

func providerAuditCount(t *testing.T, st *shipped.Stack, opEnv map[string]string, action, target string) int {
	t.Helper()
	var out struct {
		Items []struct{ Action, Target string }
	}
	st.MustCLI(t, opEnv, &out, "provider", "audit", "--query", "action="+action)
	n := 0
	for _, ev := range out.Items {
		if ev.Action == action && ev.Target == target {
			n++
		}
	}
	return n
}

// metricValue scrapes /metrics and returns the sample of series (-1 if absent).
func metricValue(t *testing.T, st *shipped.Stack, scrape, series string) float64 {
	t.Helper()
	code, body := st.Get(t, scrape, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("GET /metrics = %d", code)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if rest, ok := strings.CutPrefix(line, series+" "); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err == nil {
				return v
			}
		}
	}
	return -1
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// planeRelay is a residency plane's network path: a TCP relay on a fixed
// loopback port to the dev ClickHouse. down() refuses every connection (the
// plane is unreachable), up() serves it again on the same address.
type planeRelay struct {
	addr, target string
	mu           sync.Mutex
	ln           net.Listener
	conns        map[net.Conn]struct{}
}

func newPlaneRelay(t *testing.T, target string) *planeRelay {
	t.Helper()
	r := &planeRelay{addr: shipped.FreeAddr(t), target: target, conns: map[net.Conn]struct{}{}}
	r.up(t)
	t.Cleanup(r.down)
	return r
}

func (r *planeRelay) up(t *testing.T) {
	t.Helper()
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ { // the port may linger briefly after down()
		if ln, err = net.Listen("tcp", r.addr); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("relay %s: %v", r.addr, err)
	}
	r.mu.Lock()
	r.ln = ln
	r.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
}

func (r *planeRelay) serve(c net.Conn) {
	upstream, err := net.Dial("tcp", r.target)
	if err != nil {
		_ = c.Close()
		return
	}
	r.mu.Lock()
	if r.ln == nil {
		r.mu.Unlock()
		_ = c.Close()
		_ = upstream.Close()
		return
	}
	r.conns[c], r.conns[upstream] = struct{}{}, struct{}{}
	r.mu.Unlock()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
	_ = c.Close()
	_ = upstream.Close()
	r.mu.Lock()
	delete(r.conns, c)
	delete(r.conns, upstream)
	r.mu.Unlock()
}

func (r *planeRelay) down() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ln != nil {
		_ = r.ln.Close()
		r.ln = nil
	}
	for c := range r.conns {
		_ = c.Close()
	}
	r.conns = map[net.Conn]struct{}{}
}
