// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type pathHealthAPIFixture struct {
	fixture *roleExplanationAPIFixture
	history *capacityCounterHistoryProbe
	tests   map[string]string
	windows map[string]url.Values
}

func pathHealthTestID(t *testing.T) string {
	t.Helper()
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newPathHealthAPIFixture(t *testing.T) *pathHealthAPIFixture {
	t.Helper()
	f := newRoleExplanationAPIFixture(t)
	history := &capacityCounterHistoryProbe{Memory: flowstore.NewMemory()}
	f.server.WithFlowStore(history).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	f.server.pathStore = pathstore.NewMemory()
	tests := map[string]string{}
	windows := map[string]url.Values{}
	for lane, tenant := range f.tenants {
		tests[tenant] = pathHealthTestID(t)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permTestRead); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target) VALUES($1,$2,'health path','icmp','198.51.100.10')`, tenant, tests[tenant]); err != nil {
				return err
			}
			return store.NewEntityRegistry(f.pool).AssignPathTestContext(ctx, sc, tests[tenant], f.contextID)
		})
		f.poll(tenant, "path health interface", roleExplanationPrefixes())
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		start := f.observedAt(tenant)
		if err := f.server.pathStore.Save(pathstore.WithDiscoveryStartedAt(ctx, start), tenant, &path.Path{Target: "198.51.100.10", Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: "10.42.0.2"}}}, {TTL: 2, Nodes: []path.HopNode{{IP: "203.0.113.99"}}}}}); err != nil {
			t.Fatal(err)
		}
		reader := store.NewDeviceCounterCaptures(f.pool)
		for poll := range 2 {
			at := start.Add(time.Duration(poll) * time.Second)
			input := entity.CounterCaptureInput{ConfiguredTarget: "192.0.2.1", PollStartedAt: at, PollCompletedAt: at, PointCount: uint32(len(pathHealthMetricNames))}
			digest := [32]byte{byte(lane + 10), byte(poll + 1)}
			ref, err := reader.CaptureAuthenticated(ctx, "role-snmp", f.serials[tenant+"role-snmp"], digest, input, 128<<20)
			if err != nil {
				t.Fatal(err)
			}
			witness, err := reader.LookupWitness(ctx, "role-snmp", digest, input)
			if err != nil {
				t.Fatal(err)
			}
			var rows []flowstore.CounterRow
			for metric, name := range pathHealthMetricNames {
				value := uint64(1<<53+1) + uint64(poll)*1225000
				if metric >= 2 {
					value = 100 + uint64(poll*(lane+1))
				}
				rows = append(rows, flowstore.CounterRow{TenantID: tenant,
					CounterSource: flowstore.CounterSource{ContextID: f.contextID, DeviceID: f.routerID, AgentID: "role-snmp", SourceRef: input.ConfiguredTarget, SourceAssignedAt: witness.SourceAssignedAt, AgentAssignedAt: witness.AgentAssignedAt},
					SenderSerial:  witness.SenderSerial, CaptureKey: ref.Key, RawDigest: digest, CapturedAt: ref.CapturedAt, PollStartedAt: at, PollCompletedAt: at, Population: input.PointCount, IfIndex: 7, Name: name, Value: value, Width: 64,
					UptimeTicks: 10000 + uint32(poll)*100, UptimeKnown: true, DiscontinuityKnown: true, InterfaceSpeedBPS: 10000000, InterfaceSpeedKnown: true})
			}
			if err := history.InsertCounterPoll(ctx, rows, flowstore.CounterBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, Timeout: time.Minute}); err != nil {
				t.Fatal(err)
			}
		}
		end := start.Add(time.Second)
		if wait := time.Until(end); wait > 0 {
			if wait > 5*time.Second {
				t.Fatal("modeled source clock exceeds existing skew allowance")
			}
			time.Sleep(wait)
		}
		windows[tenant] = url.Values{"include_health": {"true"}, "health_from": {start.Add(-time.Second).Format(time.RFC3339Nano)}, "health_to": {end.Format(time.RFC3339Nano)}, "health_poll_gap": {"5s"}, "health_max_bps": {"20000000"}}
	}
	return &pathHealthAPIFixture{fixture: f, history: history, tests: tests, windows: windows}
}

func TestPathHealthServesOriginalCountersWithCurrentPairedAuthority(t *testing.T) {
	proof := newPathHealthAPIFixture(t)
	f, history, tests, windows := proof.fixture, proof.history, proof.tests, proof.windows
	socket := httptest.NewTLSServer(f.server.Handler())
	defer socket.Close()
	call := func(tenant, test string) (int, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/tests/"+test+"/path/entities?"+windows[tenant].Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	check := func(lane int, raw []byte) {
		t.Helper()
		var result struct {
			Items []pathEntityHop `json:"items"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != 2 || result.Items[0].Health == nil || len(result.Items[0].Health.Counters) != len(pathHealthMetricNames) {
			t.Fatalf("requested path health omitted the original interface counters: %s", raw)
		}
		health := result.Items[0].Health
		if health.InterfaceID != f.interfaceID || health.ContextID != f.contextID || health.Status != "observed_originals" || result.Items[1].Health == nil || result.Items[1].Health.Status != "identity_unresolved" {
			t.Fatal("path health guessed a missing interface or lost its canonical source")
		}
		in := health.Counters[0]
		if in.RateNumerator != "9800000" || in.RateDenominator != "1" || in.UtilizationNumerator != "98" || in.UtilizationDenominator != "1" || in.RateKind != "exact_under_explicit_physical_bound" || in.CaptureKey == "" || in.PreviousCaptureKey == "" || in.PreviousValue != "9007199254740993" {
			t.Fatal("served path health changed exact original counters, source citations or hand utilization", in)
		}
		if health.Counters[2].MinimumDelta != strconv.Itoa(lane+1) || health.Counters[2].RateKind != "minimum_under_counter_continuity" || strings.Contains(string(raw), f.tenants[1-lane]) {
			t.Fatal("path health lost rising error evidence or crossed tenants")
		}
	}
	read := func(lane int) {
		t.Helper()
		code, raw := call(f.tenants[lane], tests[f.tenants[lane]])
		if code != http.StatusOK {
			t.Fatal("served original path health failed", code, string(raw))
		}
		check(lane, raw)
	}
	read(0)
	read(1)
	ca := filepath.Join(t.TempDir(), "path-health-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		params := windows[tenant]
		include, from, to, gap, maximum := true, params.Get("health_from"), params.Get("health_to"), params.Get("health_poll_gap"), params.Get("health_max_bps")
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		result, err := client.GetPathEntities(t.Context(), sdk.GetPathEntitiesRequest{Id: tests[tenant], IncludeHealth: &include, HealthFrom: &from, HealthTo: &to, HealthPollGap: &gap, HealthMaxBps: &maximum})
		if err != nil {
			t.Fatal("generated HTTPS path health client failed", err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		check(lane, raw)
		args := []string{"--json", "entities", "path-resolve", tests[tenant]}
		for key, values := range params {
			args = append(args, "--query", key+"="+values[0])
		}
		var stdout, stderr bytes.Buffer
		getenv := func(key string) string {
			return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
		}
		if code := cli.RunWithStdin(args, getenv, nil, &stdout, &stderr); code != 0 {
			t.Fatal("verified HTTPS path health CLI failed", code, stderr.String())
		}
		check(lane, stdout.Bytes())
	}
	if code, raw := call(f.tenants[0], tests[f.tenants[1]]); code == http.StatusOK || strings.Contains(string(raw), "capture_key") {
		t.Fatal("foreign path returned another tenant's health", code)
	}
	// Two current ports on the same resolved device cannot be collapsed into
	// one by the parent-device address projection.
	a := f.tenants[0]
	at := f.observedAt(a)
	source := entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}
	claims := []entity.Observation{
		{ID: pathHealthTestID(t), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "8"}, SourceRef: "snmp:ifIndex:8", ObservedAt: at},
		{ID: pathHealthTestID(t), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.2"}, SourceRef: "snmp:ifIndex:8", ObservedAt: at},
	}
	accepted, unresolved, err := writeEntityEvidenceBatchForTest(tenancy.WithTenant(t.Context(), tenancy.ID(a)), store.NewEntityRegistry(f.pool), "role-snmp", f.serials[a+"role-snmp"], claims)
	if err != nil || accepted != 2 || unresolved != 0 {
		t.Fatal("paired interface ambiguity prerequisite failed", accepted, unresolved, err)
	}
	if code, raw := call(a, tests[a]); code != http.StatusOK || !strings.Contains(string(raw), "interface_unresolved_or_ambiguous") || strings.Contains(string(raw), "capture_key") {
		t.Fatal("same-device ambiguous address chose a counter port", code, string(raw))
	}
	read(1)
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_evidence WHERE tenant_id=$1 AND observation_id=ANY($2::uuid[])`, a, []string{claims[0].ID, claims[1].ID})
		return err
	})
	read(0)
	// Injected history must never cross the canonical tenant/source boundary,
	// and an error after a backend prefix must never produce partial health.
	for _, transform := range []func([]flowstore.CounterRow) ([]flowstore.CounterRow, error){
		func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
			rows[0].TenantID = f.tenants[1]
			return rows, nil
		},
		func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
			rows[0].DeviceID = "foreign-device"
			return rows, nil
		},
		func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
			rows[0].RawDigest[0] ^= 1
			return rows, nil
		},
		func(rows []flowstore.CounterRow) ([]flowstore.CounterRow, error) {
			return rows[:1], flowstore.ErrCounterHistoryBudget
		},
	} {
		history.transform = transform
		if code, raw := call(f.tenants[0], tests[f.tenants[0]]); code == http.StatusOK || strings.Contains(string(raw), "capture_key") {
			t.Fatal("foreign, forged or partial backend health escaped", code)
		}
		history.transform = nil
		read(1)
	}
	// Current role withdrawal happens after the original counter read, before
	// its result can be published. The sibling retains the same hand result.
	for _, permission := range []string{permTestRead, "entities.read", "metrics.read"} {
		history.after = func() {
			history.after = nil
			f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
				return err
			})
		}
		if code, raw := call(a, tests[a]); code == http.StatusOK || strings.Contains(string(raw), "capture_key") {
			t.Fatal("withdrawn current grant published original path counter data", permission, code)
		}
		read(1)
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
		})
	}
	history.after = func() {
		history.after = nil
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM entity_evidence WHERE tenant_id=$1 AND context_id=$2 AND alias_kind='address' AND alias_value='10.42.0.2'`, a, f.contextID)
			return err
		})
	}
	if code, raw := call(a, tests[a]); code == http.StatusOK || strings.Contains(string(raw), "capture_key") {
		t.Fatal("withdrawn original interface address published counters", code)
	}
	read(1)
	t.Log("real-integration: verified HTTPS API/SDK/CLI, application-role PG/RLS, canonical current interface/receipt grants and late withdrawal with sibling survival; path, SNMP polls, clocks and counter-history backend modeled; physical traceroute/SNMP, commercial release image and remaining FX10 surfaces are separate")
}
