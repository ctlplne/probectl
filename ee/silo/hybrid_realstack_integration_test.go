// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twmb/franz-go/pkg/kgo"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/ee/silo"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// TestHybridIsolationRealStack is the real-stack receipt for F52 (pooled,
// siloed and hybrid isolation): the operator path through the public API, CLI
// and console, and each model's isolation on real ClickHouse, the real bus and
// the object store, across three tenants.
//
// The stack is the shipped control plane (probectl-control serve, built from
// this tree with the license key baked in) on the dev stack: a fresh
// PostgreSQL database served by the least-privilege login TEN-01 ships and
// migrated by the privileged one, Kafka, ClickHouse for every telemetry plane
// with DB-level tenant scoping on, Prometheus, a filesystem object store, the
// real IdP (Dex) as the deployment IdP, TLS on every listener, on an MSP
// license. Agents are the shipped probectl-agent, enrolled with one-time join
// tokens.
//
//  1. Operator path: the operator onboards (bootstrap, TOTP, login) and
//     provisions a pooled tenant through the API, a hybrid one through the
//     CLI and a siloed one through the rendered console. Provisioning creates
//     the hybrid and siloed tenants' ClickHouse databases with every plane's
//     tables, and the siloed tenant's Postgres schema, before it returns.
//  2. Each tenant's admin signs in through the IdP; `probectl isolation
//     status` reports the effective model and that tenant's own targets.
//  3. ClickHouse: each tenant's OTLP traces, posted to the shipped OTLP/HTTP
//     listener, ride its bus lane and land in its own database — the hybrid and
//     siloed tenants' in their per-tenant databases, never the shared table —
//     and read back only for their owner.
//  4. Bus and object store: a browser canary per tenant fails against a local
//     page; the hybrid tenant's results ride its namespaced lane, never the
//     shared one, and its failure artifact lands under silo/<id>/ (its agent
//     declares the model), the pooled tenant's under tenant/<id>/.
//  5. The operator renames the hybrid tenant with `probectl isolation
//     set-tenant`; its routing is unchanged. The console (loading without a
//     server error) and the tenant's own admin page show each model, and the
//     operator's audit view records every provisioning.
func TestHybridIsolationRealStack(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "f52", TenantBand: 4})
	op := st.OnboardOperator(t, "root@msp-f52.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	slugP, slugH, slugS := "f52-pool-"+run, "f52-hyb-"+run, "f52-silo-"+run

	// 1. The operator path, one model per surface.
	P := provisionThroughAPI(t, st, op, slugP, "Pooled Industries", "pooled")
	var tenantH struct{ ID string }
	st.MustCLI(t, opEnv, &tenantH, "provider", "create-tenant", "--body",
		fmt.Sprintf(`{"slug":%q,"name":"Hybrid Industries","isolation_model":"hybrid"}`, slugH))
	H := tenantH.ID
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/provider",
		Cookies:        []testsupport.RenderCookie{{Name: auth.ProviderSessionCookie, Value: op}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Tenants", slugP, slugH},
		Steps: []testsupport.RenderStep{
			{Fill: `input[placeholder="acme"]`, Value: slugS},
			{Fill: `input[placeholder="Acme Industries"]`, Value: "Siloed Industries"},
			{Select: `select:has(option[value="hybrid"])`, Value: "siloed"},
			{Click: "Provision", Expect: []string{slugS}},
		},
	})
	inventory := isolationTenants(t, st, opEnv)
	S := inventory[slugS].ID
	for slug, want := range map[string]string{slugP: "pooled", slugH: "hybrid", slugS: "siloed"} {
		if got := inventory[slug]; got.IsolationModel != want || got.Status != "active" {
			t.Fatalf("tenant %s in `probectl isolation tenants` = %+v, want %s and active", slug, got, want)
		}
	}
	databases := chColumn(t, `SELECT name FROM system.databases`)
	for tenant, want := range map[string]bool{P: false, H: true, S: true} {
		if got := databases[silo.CHDatabase(tenant)]; got != want {
			t.Errorf("ClickHouse database %s exists = %v after provisioning, want %v", silo.CHDatabase(tenant), got, want)
		}
	}
	for _, tenant := range []string{H, S} {
		tables := chColumn(t, fmt.Sprintf(`SELECT name FROM system.tables WHERE database = '%s'`, silo.CHDatabase(tenant)))
		for _, plane := range []string{"probectl_flows", "probectl_otel_spans", "probectl_otel_logs"} {
			if !tables[plane] {
				t.Errorf("tenant %s's database lacks the %s plane's table (has %v)", tenant, plane, keys(tables))
			}
		}
	}
	schemas := pgSchemas(t, st)
	for tenant, want := range map[string]bool{P: false, H: false, S: true} {
		if got := schemas[silo.SchemaName(tenant)]; got != want {
			t.Errorf("Postgres schema %s exists = %v, want %v (only siloed moves control state)", silo.SchemaName(tenant), got, want)
		}
	}

	// 2. Each tenant's admin signs in through the IdP and reads its posture.
	scopes := []string{"tenant.read", "test.read", "metrics.read", "metrics.write"}
	admins := map[string]string{}
	for tenant, who := range map[string][2]string{
		P: {"ada@acme.example", "Pooled Industries"}, H: {"bob@globex.example", "Hybrid Industries"},
		S: {"carla@acme.example", "Siloed Industries"},
	} {
		admins[tenant] = st.SignIn(t, tenant, who[0], who[1])
	}
	tokens := map[string]string{}
	for tenant, cookie := range admins {
		tokens[tenant] = st.APIToken(t, cookie, scopes...)
	}
	statusP, statusH, statusS := isolationStatus(t, st, tokens[P]), isolationStatus(t, st, tokens[H]), isolationStatus(t, st, tokens[S])
	if statusP.EffectiveModel != "pooled" || statusP.SiloRouting.ClickHouseDatabase != "" || statusP.SiloRouting.ObjectPrefix != "" {
		t.Errorf("the pooled tenant's isolation status = %+v", statusP)
	}
	if statusH.EffectiveModel != "hybrid" || statusH.SiloRouting.ClickHouseDatabase != silo.CHDatabase(H) ||
		statusH.SiloRouting.PGSchema != "" || statusH.SiloRouting.ObjectPrefix != "silo/"+H ||
		statusH.LaneNamespace.Namespace != "t-"+slugH {
		t.Errorf("the hybrid tenant's isolation status = %+v", statusH)
	}
	if statusS.EffectiveModel != "siloed" || statusS.SiloRouting.PGSchema != silo.SchemaName(S) ||
		statusS.SiloRouting.ClickHouseDatabase != silo.CHDatabase(S) {
		t.Errorf("the siloed tenant's isolation status = %+v", statusS)
	}

	// 3. ClickHouse legs: OTLP traces through the shipped listener.
	services := map[string]string{P: "f52-svc-pool-" + run, H: "f52-svc-hyb-" + run, S: "f52-svc-silo-" + run}
	for tenant, service := range services {
		postTrace(t, st, otlpToken(t, st, admins[tenant]), service)
	}
	shared := "default.probectl_otel_spans"
	for tenant, service := range services {
		own := shared
		if tenant != P {
			own = silo.CHDatabase(tenant) + ".probectl_otel_spans"
		}
		shipped.Await(t, "tenant "+tenant+"'s spans in "+own, 60*time.Second, func() bool {
			return chCount(t, fmt.Sprintf(`SELECT count() FROM %s WHERE tenant_id = '%s' AND service = '%s'`, own, tenant, service)) > 0
		})
		if tenant != P {
			if n := chCount(t, fmt.Sprintf(`SELECT count() FROM %s WHERE tenant_id = '%s'`, shared, tenant)); n != 0 {
				t.Errorf("tenant %s's spans reached the shared table (%d rows)", tenant, n)
			}
		}
		for other, otherService := range services {
			got := traceServices(t, st, tokens[tenant], otherService)
			if want := other == tenant; got != want {
				t.Errorf("tenant %s reads %s's trace through /v1/otlp/traces = %v, want %v", tenant, other, got, want)
			}
		}
	}
	if n := laneCount(t, "probectl.t-"+slugH+".otlp.traces", H); n == 0 {
		t.Errorf("no OTLP trace on the hybrid tenant's lane probectl.t-%s.otlp.traces", slugH)
	}
	if n := laneCount(t, "probectl.otlp.traces", H); n != 0 {
		t.Errorf("the hybrid tenant's OTLP traces rode the shared lane (%d records)", n)
	}

	// 4. Bus and object store: one failing browser canary per tenant.
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "<html><body>f52 checkout is down for "+r.URL.Query().Get("for")+"</body></html>")
	}))
	t.Cleanup(page.Close)
	agents := map[string]string{P: uuid.NewString(), H: uuid.NewString()}
	for tenant, isolation := range map[string]string{P: "", H: "hybrid"} {
		name := "f52-agent-" + tenant[:8]
		dir := st.EnrollAgent(t, tenant, agents[tenant], name)
		declared := ""
		if isolation != "" {
			declared = "\n  isolation: " + isolation
		}
		st.StartAgent(t, dir, name, []string{"browser"}, fmt.Sprintf(`artifact_store:
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
`, st.ObjectDir, declared, page.URL+"/checkout?for="+tenant))
	}
	for tenant := range agents {
		shipped.Await(t, "tenant "+tenant+"'s browser result in /v1/results/latest", 90*time.Second, func() bool {
			return hasResult(t, st, tokens[tenant], agents[tenant])
		})
	}
	for tenant := range agents {
		for other, agent := range agents {
			if other != tenant && hasResult(t, st, tokens[tenant], agent) {
				t.Errorf("tenant %s reads tenant %s's browser result", tenant, other)
			}
		}
	}
	if laneCount(t, "probectl.t-"+slugH+".network.results", H) == 0 {
		t.Errorf("no result on the hybrid tenant's lane probectl.t-%s.network.results", slugH)
	}
	if n := laneCount(t, "probectl.network.results", H); n != 0 {
		t.Errorf("the hybrid tenant's results rode the shared lane (%d records)", n)
	}
	if laneCount(t, "probectl.network.results", P) == 0 {
		t.Error("no result of the pooled tenant on the shared lane")
	}
	artifactH := artifacts(t, filepath.Join(st.ObjectDir, "silo", H, "browser"))
	artifactP := artifacts(t, filepath.Join(st.ObjectDir, "tenant", P, "browser"))
	if len(artifactH) == 0 || !strings.Contains(artifactH[0], "for "+H) {
		t.Errorf("the hybrid tenant's failure artifact under silo/%s/browser = %q", H, artifactH)
	}
	if len(artifactP) == 0 || !strings.Contains(artifactP[0], "for "+P) {
		t.Errorf("the pooled tenant's failure artifact under tenant/%s/browser = %q", P, artifactP)
	}
	if _, err := os.Stat(filepath.Join(st.ObjectDir, "tenant", H)); !os.IsNotExist(err) {
		t.Errorf("the hybrid tenant wrote under the pooled namespace tenant/%s (%v)", H, err)
	}

	// 5. A rename leaves the routing alone; the console and the tenant's own
	// admin page show each model.
	st.MustCLI(t, opEnv, nil, "isolation", "set-tenant", H, "--body", `{"name":"Hybrid Holdings"}`)
	if again := isolationStatus(t, st, tokens[H]); again.SiloRouting != statusH.SiloRouting || again.LaneNamespace != statusH.LaneNamespace {
		t.Errorf("renaming the hybrid tenant moved its routing: %+v, was %+v", again, statusH)
	}
	console := testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/provider",
		Cookies:        []testsupport.RenderCookie{{Name: auth.ProviderSessionCookie, Value: op}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{slugP, slugH, slugS, "Hybrid Holdings", "hybrid", "siloed", "status-only for every isolation model"},
	})
	for _, e := range console.Errors {
		if strings.Contains(e, "HTTP 5") {
			t.Errorf("the provider console hit a server error: %s", e)
		}
	}
	var provisioned struct {
		Items []struct{ Action, Target string }
	}
	st.MustCLI(t, opEnv, &provisioned, "provider", "audit", "--query", "action=provider.tenant_provision")
	recorded := map[string]bool{}
	for _, ev := range provisioned.Items {
		if ev.Action == "provider.tenant_provision" {
			recorded[ev.Target] = true
		}
	}
	for _, tenant := range []string{P, H, S} {
		if !recorded[tenant] {
			t.Errorf("the provider audit stream has no provider.tenant_provision for %s (%+v)", tenant, provisioned.Items)
		}
	}
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/admin",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: admins[H]}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{"Data lifecycle", "Isolation:", "hybrid"},
	})
}

type tenantRow struct {
	ID             string `json:"id"`
	Slug           string `json:"slug"`
	Status         string `json:"status"`
	IsolationModel string `json:"isolation_model"`
}

type isolationPosture struct {
	EffectiveModel string `json:"effective_model"`
	LaneNamespace  struct {
		Mode      string `json:"mode"`
		Namespace string `json:"namespace"`
	} `json:"lane_namespace"`
	SiloRouting struct {
		PGSchema           string `json:"pg_schema"`
		ClickHouseDatabase string `json:"clickhouse_database"`
		ObjectPrefix       string `json:"object_prefix"`
	} `json:"silo_routing"`
}

func provisionThroughAPI(t *testing.T, st *shipped.Stack, op, slug, name, model string) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"slug": slug, "name": name, "isolation_model": model})
	req, err := http.NewRequest(http.MethodPost, st.BaseURL+"/provider/v1/tenants", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+op)
	resp, err := st.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var row tenantRow
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(body, &row) != nil || row.IsolationModel != model {
		t.Fatalf("provision %s (%s) through the API = %d: %s", slug, model, resp.StatusCode, body)
	}
	return row.ID
}

func isolationTenants(t *testing.T, st *shipped.Stack, opEnv map[string]string) map[string]tenantRow {
	t.Helper()
	var out struct{ Items []tenantRow }
	st.MustCLI(t, opEnv, &out, "isolation", "tenants")
	rows := map[string]tenantRow{}
	for _, r := range out.Items {
		rows[r.Slug] = r
	}
	return rows
}

func isolationStatus(t *testing.T, st *shipped.Stack, token string) isolationPosture {
	t.Helper()
	var out isolationPosture
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": token}, &out, "isolation", "status")
	return out
}

func otlpToken(t *testing.T, st *shipped.Stack, cookie string) string {
	t.Helper()
	code, body := st.Do(t, cookie, http.MethodPost, "/v1/otlp-tokens", map[string]string{"name": "f52-collector"})
	var out struct{ Token string }
	if code != http.StatusCreated || json.Unmarshal(body, &out) != nil || out.Token == "" {
		t.Fatalf("mint an OTLP token = %d: %s", code, body)
	}
	return out.Token
}

// postTrace sends one span over OTLP/HTTP (protobuf), as a collector would.
func postTrace(t *testing.T, st *shipped.Stack, token, service string) {
	t.Helper()
	traceID, spanID := make([]byte, 16), make([]byte, 8)
	_, _ = rand.Read(traceID)
	_, _ = rand.Read(spanID)
	now := uint64(time.Now().UnixNano())
	payload, err := proto.Marshal(&coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
			Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: service}},
		}}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
			TraceId: traceID, SpanId: spanID, Name: "checkout " + hex.EncodeToString(spanID[:4]),
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
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("OTLP/HTTP export = %d: %s", resp.StatusCode, body)
	}
}

// traceServices reports whether the caller's /v1/otlp/traces lists service.
func traceServices(t *testing.T, st *shipped.Stack, token, service string) bool {
	t.Helper()
	stdout, stderr, code := st.CLI(map[string]string{"PROBECTL_API_TOKEN": token}, "otlp", "traces", "--query", "service="+service)
	if code != 0 {
		t.Fatalf("probectl otlp traces service=%s: exit %d: %s", service, code, stderr)
	}
	return strings.Contains(stdout, service)
}

func hasResult(t *testing.T, st *shipped.Stack, token, agentID string) bool {
	t.Helper()
	var out struct {
		Items []struct {
			AgentID string `json:"agent_id"`
			Type    string `json:"type"`
		}
	}
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": token}, &out, "result", "latest")
	for _, r := range out.Items {
		if r.AgentID == agentID && r.Type == "browser" {
			return true
		}
	}
	return false
}

// laneCount counts the records on topic whose bus key names tenant.
func laneCount(t *testing.T, topic, tenant string) int {
	t.Helper()
	cl, err := kgo.NewClient(kgo.SeedBrokers(testsupport.KafkaBrokers()...), kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	n := 0
	deadline := time.Now().Add(20 * time.Second)
	for idle := 0; idle < 2 && time.Now().Before(deadline); {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		fetches := cl.PollFetches(ctx)
		cancel()
		got := 0
		fetches.EachRecord(func(r *kgo.Record) {
			got++
			if key := string(r.Key); key == tenant || strings.HasPrefix(key, tenant+"|") {
				n++
			}
		})
		if got == 0 {
			idle++
		} else {
			idle = 0
		}
	}
	return n
}

func artifacts(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil {
			out = append(out, string(raw))
		}
	}
	return out
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

func pgSchemas(t *testing.T, st *shipped.Stack) map[string]bool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	rows, err := pool.Query(context.Background(), `SELECT nspname FROM pg_namespace`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out[name] = true
	}
	return out
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
