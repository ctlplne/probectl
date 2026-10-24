// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration || isolation

package silo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

// TestSiloReaderLaneEnforcesTenantIsolationAtTheDB is DPR-323's real-stack
// proof, on a live Postgres and a live ClickHouse.
//
// Two siloed tenants are provisioned through the production provisioner: X on
// the default plane, Y on an "eu" residency plane (the same server reached at
// a second origin, so every request there carries the credentials
// internal/crypto pins to that origin, exactly as buildServeStores wires a
// real plane). Each tenant's flows and paths are written through the stores'
// routed write path. Then:
//
//  1. the boot proof (CatchUpReaderScope) passes on each populated silo;
//  2. reads through the production read path return each tenant its own rows;
//  3. at the DB: a predicate-free read sent the way the reader lane sends it,
//     as the reader login under X's tenant setting, against Y's database,
//     counts ZERO rows; under Y's own setting it counts Y's rows; and the same
//     read as the control login counts Y's rows too (without the reader lane
//     the database does not filter);
//  4. a routing bug that sends X's reads to Y's database returns X nothing;
//  5. a table created in a silo after provisioning is refused to the reader
//     until the reader scope covers it;
//  6. teardown revokes every grant the reader held on both silos.
func TestSiloReaderLaneEnforcesTenantIsolationAtTheDB(t *testing.T) {
	rawCH := os.Getenv("PROBECTL_TEST_CLICKHOUSE_URL")
	if rawCH == "" {
		rawCH = os.Getenv("PROBECTL_FLOWSTORE_URL")
	}
	if rawCH == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_CLICKHOUSE_URL / PROBECTL_FLOWSTORE_URL not set — the silo reader proof needs a real ClickHouse")
	}
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ch := newSiloReaderStack(t, rawCH)
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	X := mkTenant(t, pool, "it-rdr-x-"+stamp, "siloed", "")
	Y := mkTenant(t, pool, "it-rdr-y-"+stamp, "siloed", "eu")
	xDB, yDB := CHDatabase(X), CHDatabase(Y)
	planes := map[string]DataPlane{"eu": {Name: "eu", CHURL: ch.plane}}
	prov := NewProvisioner(pool, CHPlanes{
		Flows: ch.flow, Paths: ch.path, EBPF: ch.ebpf, Otel: ch.otel, Endpoint: ch.endpoint,
		Readers: []ReaderScope{ch.scope},
	}, planes, 0, log)
	for tenant, residency := range map[string]string{X: "", Y: "eu"} {
		if err := prov.Provision(ctx, tenant, residency, tenancy.IsolationSiloed); err != nil {
			t.Fatalf("provision %s: %v", tenant, err)
		}
		tenant, residency := tenant, residency
		t.Cleanup(func() { _ = prov.Teardown(ctx, tenant, residency, tenancy.IsolationSiloed) })
	}

	// Production routing through the registry, with a switch that plants a
	// routing bug: route[from] = to sends from's operations to to's silo.
	router := NewRouter(pool, planes, time.Second)
	var mu sync.Mutex
	misroute := map[string]string{}
	targets := func(ctx context.Context, tenant string) (tenancy.Targets, error) {
		mu.Lock()
		if to := misroute[tenant]; to != "" {
			tenant = to
		}
		mu.Unlock()
		return router.TargetsFor(ctx, tenant)
	}
	ch.flow.WithRouter(func(ctx context.Context, tenant string) (flowstore.Target, error) {
		tg, err := targets(ctx, tenant)
		return flowstore.Target{BaseURL: tg.CHBaseURL, Database: tg.CHDatabase}, err
	})
	ch.path.WithRouter(func(ctx context.Context, tenant string) (pathstore.Target, error) {
		tg, err := targets(ctx, tenant)
		return pathstore.Target{BaseURL: tg.CHBaseURL, Database: tg.CHDatabase}, err
	})

	writeSiloTelemetry(t, ch, X, 2, "198.51.100.10")
	writeSiloTelemetry(t, ch, Y, 3, "192.0.2.99")
	if n := ch.count(t, ch.controlLane(ch.plane), "SELECT count() AS n FROM "+yDB+".probectl_flows", ""); n != 3 {
		t.Fatalf("Y's silo on the eu plane holds %d flows, want 3 (routed writes)", n)
	}

	// 1. The boot proof, now that the silos hold rows to leak.
	for tenant, residency := range map[string]string{X: "", Y: "eu"} {
		if err := prov.CatchUpReaderScope(ctx, tenant, residency); err != nil {
			t.Errorf("boot reader-scope proof refused tenant %s's populated silo: %v", tenant, err)
		}
	}

	// 2. The production read path serves each tenant its own rows.
	for tenant, want := range map[string]int{X: 2, Y: 3} {
		if got := exportFlowTenants(t, ch.flow, tenant); len(got) != want || !allEqual(got, tenant) {
			t.Errorf("tenant %s's flow export through the reader lane = %v, want %d rows of its own", tenant, got, want)
		}
	}
	if p, ok, err := ch.path.Latest(ctx, X, "rdr-target.example"); err != nil || !ok || p.TargetIP != "198.51.100.10" {
		t.Errorf("tenant X's latest path through the reader lane = %+v ok=%v err=%v", p, ok, err)
	}

	// 3. The DB's own answer: predicate-free reads of each silo as the
	// reader, the way RouteRead sends them.
	for _, tc := range []struct {
		name, as, plane, db string
		want                int
	}{
		{"X's setting on Y's eu silo", X, ch.plane, yDB, 0},
		{"Y's setting on X's silo", Y, "", xDB, 0},
		{"Y's own setting on Y's eu silo", Y, ch.plane, yDB, 3},
		{"X's own setting on X's silo", X, "", xDB, 2},
	} {
		lane, err := chclient.RouteRead(true, tc.as, true, tc.plane, ch.control, ch.scope.Reader)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !lane.Reader {
			t.Fatalf("%s: RouteRead sent a scoped per-tenant read down the control lane, which no row policy filters", tc.name)
		}
		for _, table := range []string{"probectl_flows", "probectl_path_hops2"} {
			want := tc.want
			if table == "probectl_path_hops2" {
				want = min(tc.want, 1) // one path per tenant, one hop each
			}
			got := ch.count(t, lane, "SELECT count() AS n FROM "+tc.db+"."+table, tc.as)
			if got != want {
				t.Errorf("CROSS-TENANT READ at the DB: %s counted %d rows of %s, want %d", tc.name, got, table, want)
			}
		}
	}
	if n := ch.count(t, ch.controlLane(ch.plane), "SELECT count() AS n FROM "+yDB+".probectl_flows", X); n != 3 {
		t.Fatalf("non-vacuity: the control login counted %d of Y's flows under X's setting, want all 3 (it is not filtered)", n)
	}

	// 4. A routing bug sends X's reads to Y's silo: X gets nothing of Y's.
	mu.Lock()
	misroute[X] = Y
	mu.Unlock()
	if got := exportFlowTenants(t, ch.flow, X); len(got) != 0 {
		t.Errorf("CROSS-TENANT READ: X's misrouted flow export returned %v from Y's silo", got)
	}
	if p, ok, err := ch.path.Latest(ctx, X, "rdr-target.example"); err != nil || ok {
		t.Errorf("CROSS-TENANT READ: X's misrouted latest path = %+v ok=%v err=%v, want nothing", p, ok, err)
	}
	mu.Lock()
	delete(misroute, X)
	mu.Unlock()

	// 5. A table a later release adds to a silo is refused to the reader
	// until the reader scope covers it (grants are per table, never db.*).
	late := xDB + ".probectl_late_plane"
	for _, stmt := range []string{
		"CREATE TABLE " + late + " (tenant_id String, v UInt8) ENGINE = MergeTree ORDER BY tenant_id",
		"INSERT INTO " + late + " VALUES ('" + X + "', 1), ('" + Y + "', 2)",
	} {
		ch.exec(t, ch.controlLane(""), stmt)
	}
	xLane, err := chclient.RouteRead(true, X, true, "", ch.control, ch.scope.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if status, code := ch.status(t, xLane, "SELECT count() AS n FROM "+late, X); status/100 == 2 || code != "497" {
		t.Errorf("the reader read an unscoped new silo table (status %d, code %q), want ACCESS_DENIED", status, code)
	}
	if err := prov.CatchUpReaderScope(ctx, X, ""); err != nil {
		t.Fatalf("catch-up over the new table: %v", err)
	}
	if n := ch.count(t, xLane, "SELECT count() AS n FROM "+late, X); n != 1 {
		t.Errorf("after catch-up the reader counted %d rows of the new table under X's setting, want X's 1", n)
	}

	// 6. Teardown revokes the reader's grants on both silos.
	for tenant, residency := range map[string]string{X: "", Y: "eu"} {
		if err := prov.Teardown(ctx, tenant, residency, tenancy.IsolationSiloed); err != nil {
			t.Fatalf("teardown %s: %v", tenant, err)
		}
	}
	grants := ch.count(t, ch.controlLane(""), "SELECT count() AS n FROM system.grants WHERE user_name = {u:String} AND database IN ({x:String}, {y:String})",
		"", "u", ch.scope.ReaderUser, "x", xDB, "y", yDB)
	if grants != 0 {
		t.Errorf("teardown left the reader %d grants on the dropped silos", grants)
	}
}

// siloReaderStack is the five ClickHouse stores of one control plane, with
// the control and reader logins' credentials pinned per origin by
// internal/crypto, plus the reader scope the provisioner uses.
type siloReaderStack struct {
	pooled, plane string
	control       *chclient.Conn
	flow          *flowstore.ClickHouse
	path          *pathstore.ClickHouse
	ebpf          *ebpfstore.ClickHouse
	otel          *otelstore.ClickHouse
	endpoint      *endpointstore.ClickHouse
	scope         chclient.SiloScope
}

func newSiloReaderStack(t *testing.T, rawCH string) *siloReaderStack {
	t.Helper()
	u, err := url.Parse(rawCH)
	if err != nil || u.User == nil {
		t.Fatalf("ClickHouse URL %q must carry the dev stack's control login", rawCH)
	}
	controlPassword, _ := u.User.Password()
	s := &siloReaderStack{pooled: "http://localhost:" + u.Port(), plane: "http://127.0.0.1:" + u.Port()}
	readerUser, _ := chtest.ProvisionReader(t, rawCH, "silo_reader")

	dir := t.TempDir()
	controlFile := writeSiloCredential(t, dir, "control.json", u.User.Username(), controlPassword)
	readerFile := writeSiloCredential(t, dir, "reader.json", readerUser, chtest.ReaderPassword)
	factory := func(file string) *crypto.BasicAuthClientFactory {
		f, err := crypto.LoadBasicAuthClientFactory(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.WithOriginCredentialFile(s.plane, file); err != nil {
			t.Fatal(err)
		}
		return f
	}
	controlClient, err := factory(controlFile).HTTPClient(30*time.Second, s.pooled)
	if err != nil {
		t.Fatal(err)
	}
	readerClient, err := factory(readerFile).HTTPClient(30*time.Second, s.pooled)
	if err != nil {
		t.Fatal(err)
	}
	s.control = chclient.NewWithClient(controlClient)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	s.flow, err = flowstore.NewClickHouseWithClient(s.pooled, 0, controlClient)
	must(err)
	s.path, err = pathstore.NewClickHouseRetainedWithClient(s.pooled, 0, controlClient)
	must(err)
	s.ebpf, err = ebpfstore.NewClickHouseWithClient(s.pooled, 0, controlClient)
	must(err)
	s.otel, err = otelstore.NewClickHouseWithClient(s.pooled, 0, controlClient)
	must(err)
	s.endpoint, err = endpointstore.NewClickHouseWithClient(s.pooled, 0, controlClient)
	must(err)
	s.flow.WithTenantScoping(true).WithReader(readerClient)
	s.path.WithTenantScoping(true).WithReader(readerClient)

	scope, scoped := s.flow.SiloReaderScope()
	if !scoped || scope.Reader == nil {
		t.Fatal("a tenant-scoped store with a reader lane must expose its silo reader scope")
	}
	// Production binds the login through EnsureReaderRowPolicy at boot. This
	// test names it directly so it never re-binds the pooled tables' shared
	// policy under another package's concurrently running isolation test.
	scope.ReaderUser = readerUser
	s.scope = scope
	return s
}

func writeSiloCredential(t *testing.T, dir, name, user, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": password})
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func (s *siloReaderStack) controlLane(plane string) chclient.ReadLane {
	base := s.pooled
	if plane != "" {
		base = plane
	}
	return chclient.ReadLane{Conn: s.control, Base: base, Key: plane}
}

// do sends one statement down lane, with the request tenant setting when
// tenant is set (as the stores' tenant reads carry it) and server-bound
// params given as name, value pairs.
func (s *siloReaderStack) do(t *testing.T, lane chclient.ReadLane, method, sql, tenant string, params ...string) (status int, code string, body []byte) {
	t.Helper()
	q := url.Values{"query": {sql}}
	if tenant != "" {
		q.Set("SQL_probectl_tenant", tenant)
	}
	for i := 0; i+1 < len(params); i += 2 {
		q.Set("param_"+params[i], params[i+1])
	}
	req, err := http.NewRequestWithContext(context.Background(), method, lane.Base+"/?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := lane.Conn.Do(lane.Key, req)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header.Get("X-ClickHouse-Exception-Code"), body
}

func (s *siloReaderStack) count(t *testing.T, lane chclient.ReadLane, sql, tenant string, params ...string) int {
	t.Helper()
	status, _, body := s.do(t, lane, http.MethodGet, sql+" FORMAT JSONEachRow", tenant, params...)
	if status != http.StatusOK {
		t.Fatalf("%s: status %d: %s", sql, status, body)
	}
	rows, err := chclient.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	return chclient.Count(rows)
}

func (s *siloReaderStack) status(t *testing.T, lane chclient.ReadLane, sql, tenant string) (int, string) {
	t.Helper()
	status, code, _ := s.do(t, lane, http.MethodGet, sql+" FORMAT JSONEachRow", tenant)
	return status, code
}

func (s *siloReaderStack) exec(t *testing.T, lane chclient.ReadLane, sql string) {
	t.Helper()
	if status, _, body := s.do(t, lane, http.MethodPost, sql, ""); status != http.StatusOK {
		t.Fatalf("%s: status %d: %s", sql, status, body)
	}
}

// writeSiloTelemetry writes n flows and one path for tenant through the
// stores' routed write paths.
func writeSiloTelemetry(t *testing.T, s *siloReaderStack, tenant string, n int, ip string) {
	t.Helper()
	now := time.Now().UTC()
	rows := make([]flowstore.Row, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, flowstore.Row{
			TenantID: tenant, AgentID: "rdr-agent", Exporter: "192.0.2.1", Protocol: "netflow9",
			TS: now, StartTS: now.Add(-time.Second), SrcAddr: ip, DstAddr: "203.0.113.5",
			SrcPort: uint16(40000 + i), DstPort: 443, Transport: "tcp", Bytes: 100, Packets: 1, Sampling: 1,
			BytesScaled: 100, PacketsScaled: 1,
		})
	}
	if err := s.flow.Insert(context.Background(), rows); err != nil {
		t.Fatalf("insert %s flows: %v", tenant, err)
	}
	p := &path.Path{Target: "rdr-target.example", TargetIP: ip, Mode: "icmp", MaxHops: 8,
		Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: ip, Sent: 1, Received: 1}}}}}
	if err := s.path.Save(context.Background(), tenant, p); err != nil {
		t.Fatalf("save %s path: %v", tenant, err)
	}
}

// exportFlowTenants is the tenant_id of every row tenant's production flow
// export carries.
func exportFlowTenants(t *testing.T, flow *flowstore.ClickHouse, tenant string) []string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := flow.ExportTenant(context.Background(), tenant, &buf); err != nil {
		t.Fatalf("export %s: %v", tenant, err)
	}
	var out []string
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var row struct {
			TenantID string `json:"tenant_id"`
		}
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatalf("export row: %v", err)
		}
		out = append(out, row.TenantID)
	}
	return out
}

func allEqual(values []string, want string) bool {
	for _, v := range values {
		if v != want {
			return false
		}
	}
	return want != ""
}
