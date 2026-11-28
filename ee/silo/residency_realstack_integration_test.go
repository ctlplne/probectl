// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/ee/silo"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type residencyTenant struct {
	model, email, id, service, testID, cookie, token, sender string
}

const rtt06Plane = "eu"

// TestIndependentClickHouseResidencyRealStack proves RTT-06 against two
// independent, disposable ClickHouse servers, including a disconnection of
// the named residency plane and recovery with the original tenant data.
func TestIndependentClickHouseResidencyRealStack(t *testing.T) {
	const secondEnv = "PROBECTL_TEST_RTT06_SECOND_CLICKHOUSE_URL"
	secondaryRaw := os.Getenv(secondEnv)
	if secondaryRaw == "" {
		testsupport.SkipOptIn(t, secondEnv, "requires a second disposable ClickHouse server")
	}
	primary := residencyFixtureURL(t, shipped.CHURL())
	secondary := residencyFixtureURL(t, secondaryRaw)
	if primary.Host == secondary.Host || primary.User.String() == secondary.User.String() {
		t.Fatal("provide distinct ClickHouse endpoints and separate control credentials")
	}
	primaryName := residencyCHQuery(t, primary.String(), "SELECT hostName()")
	secondaryName := residencyCHQuery(t, secondaryRaw, "SELECT hostName()")
	if primaryName == "" || secondaryName == "" || primaryName == secondaryName {
		t.Fatal("the two endpoints must identify separate ClickHouse servers")
	}

	shipped.EnsureCHReader(t, secondaryRaw)
	eu := newPlaneRelay(t, secondary.Host)
	credential := filepath.Join(t.TempDir(), "secondary-control.json")
	password, _ := secondary.User.Password()
	raw, err := json.Marshal(map[string]string{"username": secondary.User.Username(), "password": password})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credential, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	secondary.Host, secondary.User = eu.addr, nil
	st := shipped.Start(t, shipped.Options{Name: "rtt06", TenantBand: 5,
		DataPlanes: map[string]string{rtt06Plane: secondary.String()},
		Env: map[string]string{
			"PROBECTL_DATAPLANE_BASIC_AUTH_FILES":       rtt06Plane + "=" + credential,
			"PROBECTL_SILO_FAILURE_MODE":                "quarantine",
			"PROBECTL_SILO_QUARANTINE_RECHECK_INTERVAL": "5s",
		}})
	operator := st.OnboardOperator(t, "rtt06-provider@msp.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": operator}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []residencyTenant{
		{model: "pooled", email: "ada@acme.example"},
		{model: "hybrid", email: "bob@globex.example"},
		{model: "siloed", email: "carla@acme.example"},
	}
	awaitQuarantineOTLPListener(t, st)
	for i := range lanes {
		lane := &lanes[i]
		location := rtt06Plane
		if lane.model == "pooled" {
			location = ""
		}
		lane.service = "rtt06-" + lane.model + "-" + run
		name := "Residency " + lane.model
		var created tenantRow
		st.MustCLI(t, opEnv, &created, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q,"residency":%q}`, lane.service, name, lane.model, location))
		id, err := uuid.Parse(created.ID)
		if err != nil || id.String() != created.ID || created.IsolationModel != lane.model {
			t.Fatal("the provider did not create the requested residency tenant")
		}
		lane.id = created.ID
		lane.cookie = st.SignIn(t, lane.id, lane.email, name)
		lane.token = st.APIToken(t, lane.cookie, "tenant.read", "test.read", "metrics.read")
		lane.sender = otlpToken(t, st, lane.cookie)
		lane.testID = createResidencyWitnessTest(t, st, lane.cookie)
		postTrace(t, st, lane.sender, lane.service)
	}

	pool, err := pgxpool.New(t.Context(), st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, lane := range lanes {
		checkResidencyPlacement(t, st, pool, primary.String(), secondaryRaw, lane)
		for _, sibling := range lanes {
			if sibling.id == lane.id {
				continue
			}
			if code, _ := st.Do(t, sibling.cookie, http.MethodGet, "/v1/tests/"+lane.testID, nil); code != http.StatusNotFound {
				t.Fatalf("%s could probe the %s test through HTTP %d", sibling.model, lane.model, code)
			}
			if traceServices(t, st, sibling.token, lane.service) {
				t.Fatalf("%s could read the %s trace with its own token", sibling.model, lane.model)
			}
		}
	}
	t.Run("eu-disconnect-refuses-only-resident-tenants", func(t *testing.T) {
		verifyIndependentResidencyOutage(t, st, eu, primary.String(), secondaryRaw, lanes[0], lanes[1:])
	})
}

func verifyIndependentResidencyOutage(t *testing.T, st *shipped.Stack, eu *planeRelay, primary, secondary string, pooled residencyTenant, residents []residencyTenant) {
	t.Helper()
	eu.down()
	st.RestartControl(t, "rtt06-eu-disconnected", nil)
	awaitQuarantineOTLPListener(t, st)
	for _, lane := range residents {
		code, body := st.Do(t, lane.cookie, http.MethodGet, "/v1/otlp/traces?service="+lane.service, nil)
		assertQuarantined(t, lane.model+" trace read", code, body)
		if code := postSpan(t, st, lane.sender, lane.service+"-refused"); code != http.StatusServiceUnavailable {
			t.Fatalf("%s trace export during eu loss = %d, want retryable 503", lane.model, code)
		}
	}
	awaitTrace(t, st, pooled.token, pooled.service)
	pooledDuring := pooled.service + "-during"
	postTrace(t, st, pooled.sender, pooledDuring)
	awaitTrace(t, st, pooled.token, pooledDuring)

	eu.up(t)
	for _, lane := range residents {
		shipped.Await(t, lane.model+" leaves quarantine when eu returns", 60*time.Second, func() bool {
			code, _ := st.Do(t, lane.cookie, http.MethodGet, "/v1/tests/"+lane.testID, nil)
			return code == http.StatusOK
		})
		awaitTrace(t, st, lane.token, lane.service)
		postTrace(t, st, lane.sender, lane.service+"-after")
		awaitTrace(t, st, lane.token, lane.service+"-after")
		if traceServices(t, st, pooled.token, lane.service) || traceServices(t, st, lane.token, pooledDuring) {
			t.Fatalf("%s and pooled readers saw each other's traces after eu recovered", lane.model)
		}
		predicate := fmt.Sprintf(".probectl_otel_spans FINAL WHERE service = '%s'", lane.service+"-refused")
		if residencyCHQuery(t, primary, "SELECT count() FROM default"+predicate) != "0" ||
			residencyCHQuery(t, secondary, "SELECT count() FROM "+silo.CHDatabase(lane.id)+predicate) != "0" {
			t.Fatalf("the refused %s trace was written during eu loss", lane.model)
		}
	}
}

func residencyFixtureURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || (u.Scheme != "http" && u.Scheme != "https") {
		t.Fatal("a disposable ClickHouse fixture needs a loopback HTTP or HTTPS endpoint and test credentials")
	}
	addr, err := netip.ParseAddrPort(u.Host)
	if err != nil || !addr.Addr().IsLoopback() || addr.Port() < 1024 || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("provide a loopback ClickHouse fixture on a high port")
	}
	return u
}

func residencyCHQuery(t *testing.T, target, statement string) string {
	t.Helper()
	reply, err := shipped.CHQuery(target, statement)
	if err != nil {
		t.Fatalf("fixture ClickHouse query: %v", err)
	}
	return strings.TrimSpace(reply)
}

func createResidencyWitnessTest(t *testing.T, st *shipped.Stack, cookie string) string {
	t.Helper()
	code, raw := st.Do(t, cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": "Residency storage witness", "type": "http", "target": "http://127.0.0.1:18080/",
		"interval_seconds": 60, "timeout_seconds": 5, "enabled": false,
		"params": map[string]string{"allow_private_targets": "true"},
	})
	var body struct{ ID string }
	if code != http.StatusCreated || json.Unmarshal(raw, &body) != nil || body.ID == "" {
		t.Fatalf("shipped API did not create the tenant's storage witness: HTTP %d", code)
	}
	return body.ID
}

func checkResidencyPlacement(t *testing.T, st *shipped.Stack, pool *pgxpool.Pool, primary, secondary string, lane residencyTenant) {
	t.Helper()
	if code, _ := st.Do(t, lane.cookie, http.MethodGet, "/v1/tests/"+lane.testID, nil); code != http.StatusOK {
		t.Fatalf("%s could not read its own test: HTTP %d", lane.model, code)
	}
	awaitTrace(t, st, lane.token, lane.service)
	status := isolationStatus(t, st, lane.token)
	if status.EffectiveModel != lane.model {
		t.Fatalf("%s did not retain its configured isolation model", lane.model)
	}
	var residency string
	if err := pool.QueryRow(t.Context(), "SELECT residency FROM public.tenants WHERE id=$1::uuid", lane.id).Scan(&residency); err != nil {
		t.Fatalf("inspect %s residency registry: %v", lane.model, err)
	}
	wantResidency := rtt06Plane
	if lane.model == "pooled" {
		wantResidency = ""
	}
	if residency != wantResidency {
		t.Fatalf("%s residency = %q, want %q", lane.model, residency, wantResidency)
	}

	schema, wantSchema := "public", ""
	if lane.model == "siloed" {
		schema = silo.SchemaName(lane.id)
		wantSchema = schema
		if residencyPostgresTestCount(t, pool, "public", lane) != 0 {
			t.Fatal("siloed test was written to the pooled PostgreSQL table")
		}
	}
	if status.SiloRouting.PGSchema != wantSchema || residencyPostgresTestCount(t, pool, schema, lane) != 1 {
		t.Fatalf("%s test was not written to its expected PostgreSQL schema", lane.model)
	}

	const spans = "probectl_otel_spans"
	owned := fmt.Sprintf(" WHERE tenant_id = '%s' AND service = '%s'", lane.id, lane.service)
	pooled := "SELECT count() FROM default." + spans + " FINAL" + owned
	if lane.model == "pooled" {
		if status.SiloRouting.ClickHouseDatabase != "" || residencyCHQuery(t, primary, pooled) != "1" {
			t.Fatal("the pooled trace did not land on the primary ClickHouse server")
		}
		catalog := "SELECT count() FROM system.tables WHERE database = 'default' AND name = '" + spans + "'"
		if residencyCHQuery(t, secondary, catalog) != "0" && residencyCHQuery(t, secondary, pooled) != "0" {
			t.Fatal("the pooled trace was also written to the secondary ClickHouse server")
		}
		return
	}
	db := silo.CHDatabase(lane.id)
	onPrimary := "SELECT count() FROM system.databases WHERE name = '" + db + "'"
	onSecondary := "SELECT count() FROM " + db + "." + spans + " FINAL" + owned
	secondaryTotal := "SELECT count() FROM " + db + "." + spans + " FINAL"
	if status.SiloRouting.ClickHouseDatabase != db || residencyCHQuery(t, secondary, onSecondary) != "1" ||
		residencyCHQuery(t, secondary, secondaryTotal) != "1" {
		t.Fatalf("%s trace did not land in its own database on the named secondary server", lane.model)
	}
	if residencyCHQuery(t, primary, onPrimary) != "0" || residencyCHQuery(t, primary, pooled) != "0" {
		t.Fatalf("%s database or trace appeared on the primary ClickHouse server", lane.model)
	}
}

func residencyPostgresTestCount(t *testing.T, pool *pgxpool.Pool, schema string, lane residencyTenant) int {
	t.Helper()
	table := pgx.Identifier{schema, "tests"}.Sanitize()
	var count int
	err := pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table+" WHERE tenant_id=$1::uuid AND id=$2::uuid", lane.id, lane.testID).Scan(&count)
	if err != nil {
		t.Fatalf("inspect the %s storage witness: %v", lane.model, err)
	}
	return count
}
