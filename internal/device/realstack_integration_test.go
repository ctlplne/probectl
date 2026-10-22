// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package device_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/bus"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// snmpdBase is the base of the lab's SNMP agents: Alpine 3.22.6, pinned by
// digest. The agents run net-snmp's snmpd from that release's own package
// repository (net-snmp 5.9.4 on 3.22), the agent most network gear and every
// Linux host speaks, so the device agent talks to a real SNMP engine rather
// than a recorded walk.
const snmpdBase = "alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

// burstBytes is the traffic each tenant's device sends between two polls: the
// interface counter must move by at least this much on every surface.
const burstBytes = 4000 * 1400

// pollInterval is the device agent's poll cadence for the lab devices: the
// shortest the collection profiles accept as an override.
const pollInterval = 15 * time.Second

// TestDeviceTelemetryRealStack is the real-stack receipt for device telemetry
// (F18): an MSP's two tenants each point the SHIPPED probectl-device-agent at
// their own SNMP device, and each sees its device's live telemetry, its LLDP
// neighbor and its collection receipts through the public API, the CLI and
// the rendered Device page, and nothing of the other's.
//
// The devices are real SNMP agents: one net-snmp snmpd container per tenant,
// each publishing UDP 161 on a loopback port docker picks. Both devices are
// polled at the same address, 127.0.0.1, so a read that loses its tenant scope
// returns the other tenant's device under the same name. They differ in
// everything a device can say about itself:
//
//   - Tenant A (pooled) polls "acme-core-sw1" over SNMPv3 authPriv (SHA/AES).
//     The username is plain config; both passphrases are SECRET REFERENCES
//     (env:...) the agent resolves through its secrets resolver, the
//     credential locator docs/device-telemetry.md describes. A's device
//     reports one LLDP neighbor, "acme-dist-sw2" on Gi0/48.
//   - Tenant B (hybrid) polls "globex-edge-r1" over SNMPv2c; its community is
//     a secret reference too. B's device reports "globex-core-r9" on xe-0/0/1.
//
// LLDP-MIB rows are served by snmpd itself (override directives), read over
// the same authenticated session as every other walk.
//
// The stack is the shipped control plane on the four-store profile
// (shipped.Start): least-privilege PostgreSQL, Kafka with strict tenant
// lanes, ClickHouse, Prometheus as the TSDB, TLS everywhere, the real IdP
// (production session auth in Chromium) and an MSP license.
//
//  1. A registers its device collector through the API (topology-rich
//     profile), B with `probectl agent enroll-token` + `probectl collector
//     register` (standard profile, neighbors enabled by override). Each gets
//     its own bus lane, and each agent runs on the YAML its registration
//     hands back.
//  2. Each agent polls its device and publishes on its lane; the control
//     plane lands the samples in the TSDB, the topology graph and the
//     forced-RLS neighbor and outcome tables. GET /v1/device/metrics and
//     `probectl device metrics` show each tenant its own device (name,
//     agent, interfaces, uptime) and only it; GET /v1/devices and `probectl
//     device list` list it; the device and metric filters reach nothing of
//     the other tenant's even though both devices share 127.0.0.1.
//  3. Each device then sends burstBytes out of eth0. Its ifHCOutOctets must
//     rise by at least that much on the API and the CLI within two polls, and
//     never past what the device's own kernel counted: live counters, not a
//     replayed sample. In the TSDB each device's series carry exactly its own
//     tenant and agent.
//  4. GET /v1/device/neighbors and `probectl device neighbors` show each
//     tenant its own LLDP neighbor (current); GET
//     /v1/device/collection-outcomes and `probectl device outcomes` show
//     LLDP ok_with_rows with one row and CDP healthy_empty. As the app role, a
//     predicate-free count of either table scoped to a tenant is exactly the
//     tenant's: PostgreSQL row security isolates.
//  5. Traps: each agent listens for traps from its device only. Each device
//     sends one authenticated linkDown (A: SNMPv3 authPriv, B: v2c); a trap
//     with the wrong credential and B's trap sent to A's listener are refused.
//     The control plane has no trap read model yet (docs/device-telemetry.md),
//     so the trap leg asserts the bus: each tenant's trap-events lane holds
//     exactly its own trap, attributed to its tenant and agent, and nothing
//     else; the shared lane holds none of this run's.
//  6. The rendered Device page shows each tenant its device, its neighbor
//     and its live interface telemetry, and never the other's.
//  7. No passphrase or community appears in a log, an API or CLI response,
//     the rendered page or any record on either tenant's device lanes.
func TestDeviceTelemetryRealStack(t *testing.T) {
	lab := startSNMPLab(t)
	st := shipped.Start(t, shipped.Options{Name: "devicetel", TenantBand: 4})
	op := st.OnboardOperator(t, "root@msp-device.example")
	opEnv := map[string]string{"PROBECTL_API_TOKEN": op}
	run := strconv.FormatInt(time.Now().UnixNano(), 36)

	A := &deviceTenant{slug: "dev-acme-" + run, name: "Device Acme", model: "pooled", admin: "ada@acme.example",
		profile: "topology-rich", sysName: "acme-core-sw1", neighbor: "acme-dist-sw2", neighborPort: "Gi0/48",
		transport: "snmpv3", credential: "acme-core-ro", user: "acme-ro",
		authPass: "acme-auth-words-" + run, privPass: "acme-priv-words-" + run}
	B := &deviceTenant{slug: "dev-globex-" + run, name: "Device Globex", model: "hybrid", admin: "bob@globex.example",
		profile: "standard", sysName: "globex-edge-r1", neighbor: "globex-core-r9", neighborPort: "xe-0/0/1",
		transport: "snmpv2c", credential: "globex-edge-ro", community: "globex-community-words-" + run}
	tenants := []*deviceTenant{A, B}
	for _, tn := range tenants {
		var row struct{ ID string }
		st.MustCLI(t, opEnv, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tn.slug, tn.name, tn.model))
		tn.id = row.ID
		tn.cookie = st.SignIn(t, tn.id, tn.admin, tn.name)
		tn.token = st.APIToken(t, tn.cookie, "tenant.read", "agent.write", "metrics.read", "topology.read")
		tn.device = lab.startDevice(t, tn)
	}

	// 1. Registration: A through the API, B through the CLI.
	A.registerAPI(t, st)
	B.registerCLI(t, st)
	for _, tn := range tenants {
		tn.startAgent(t, st, lab)
	}

	// 2. Each tenant's telemetry, through the API and the CLI.
	for _, tn := range tenants {
		tn.awaitMetrics(t, st, 120*time.Second)
	}
	for _, tn := range tenants {
		tn.checkMetricSurfaces(t, st, tenants)
		tn.checkInventory(t, st, tenants)
	}

	// 3. Live counters: each device moves its own eth0 counter.
	for _, tn := range tenants {
		tn.checkCounterMoves(t, st)
	}
	checkTSDBAttribution(t, tenants)

	// 4. Physical adjacency and collection receipts.
	for _, tn := range tenants {
		tn.awaitNeighbors(t, st, 90*time.Second)
	}
	for _, tn := range tenants {
		tn.checkNeighborSurfaces(t, st, tenants)
		tn.checkOutcomeSurfaces(t, st, tenants)
	}
	for _, table := range []string{"device_neighbor_evidence", "device_collection_outcomes"} {
		for _, tn := range tenants {
			own, seen, total := rlsCounts(t, st, table, tn.id)
			if own == 0 || seen != own || own >= total {
				t.Errorf("as the app role scoped to %s, a predicate-free count of %s saw %d rows; the tenant owns %d of %d: the storage layer is not enforcing tenant isolation",
					tn.slug, table, seen, own, total)
			}
		}
	}

	// 5. Traps, on each tenant's lane.
	checkTraps(t, tenants)

	// 6. The rendered Device page, as each tenant's admin.
	for _, tn := range tenants {
		tn.renderPage(t, st, tenants)
	}

	// 7. No credential leaves the device, the agent's resolver or the wire
	// format it was meant for.
	checkNoSecrets(t, st, tenants)
}

// --- the tenants ---

type deviceTenant struct {
	slug, name, model, admin string
	profile, sysName         string
	neighbor, neighborPort   string
	transport, credential    string
	user, authPass, privPass string
	community                string
	id, cookie, token        string
	collectorID, lane        string
	device                   *snmpDevice
	agentLog                 string
	trapListen, trapSource   string
	hint                     map[string]any
	seen                     [][]byte // every API/CLI body and rendered page text, for the secret check
	mu                       sync.Mutex
	outOctetsLast            float64 // eth0 out-octets on the API after the burst
}

func (tn *deviceTenant) env() map[string]string {
	return map[string]string{"PROBECTL_API_TOKEN": tn.token}
}

// secrets are the credential values the tenant's device and agent share.
func (tn *deviceTenant) secrets() []string {
	var out []string
	for _, s := range []string{tn.authPass, tn.privPass, tn.community} {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (tn *deviceTenant) keep(raw []byte) {
	tn.mu.Lock()
	tn.seen = append(tn.seen, append([]byte(nil), raw...))
	tn.mu.Unlock()
}

func (tn *deviceTenant) get(t *testing.T, st *shipped.Stack, route string, out any) {
	t.Helper()
	code, raw := st.Do(t, tn.cookie, http.MethodGet, route, nil)
	tn.keep(raw)
	if code != http.StatusOK || json.Unmarshal(raw, out) != nil {
		t.Fatalf("GET %s as %s = %d: %.400s", route, tn.slug, code, raw)
	}
}

func (tn *deviceTenant) cli(t *testing.T, st *shipped.Stack, out any, args ...string) {
	t.Helper()
	stdout, stderr, code := st.CLI(tn.env(), args...)
	tn.keep([]byte(stdout + stderr))
	if code != 0 {
		t.Fatalf("probectl %s as %s: exit %d: %s%s", strings.Join(args, " "), tn.slug, code, stderr, stdout)
	}
	if out != nil {
		if err := json.Unmarshal([]byte(stdout), out); err != nil {
			t.Fatalf("probectl %s as %s: decode %q: %v", strings.Join(args, " "), tn.slug, stdout, err)
		}
	}
}

type registration struct {
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	Plane    string `json:"plane"`
	Config   struct {
		Env  map[string]string `json:"env"`
		YAML map[string]any    `json:"yaml"`
	} `json:"config"`
}

// bind checks a plane=device registration and keeps the collector id, the
// tenant's lane and the YAML the registration hands back.
func (tn *deviceTenant) bind(t *testing.T, surface string, reg registration) {
	t.Helper()
	env, yaml := reg.Config.Env, reg.Config.YAML
	lane, _ := yaml["bus"].(map[string]any)
	if reg.TenantID != tn.id || reg.Plane != "device" || reg.AgentID == "" ||
		env["PROBECTL_DEVICE_TENANT"] != tn.id || env["PROBECTL_DEVICE_AGENT_ID"] != reg.AgentID ||
		env["PROBECTL_DEVICE_PROFILE"] != tn.profile || env["PROBECTL_DEVICE_BUS_NAMESPACE"] == "" ||
		yaml["tenant_id"] != tn.id || yaml["agent_id"] != reg.AgentID || yaml["collection_profile"] != tn.profile ||
		lane == nil || lane["namespace"] != env["PROBECTL_DEVICE_BUS_NAMESPACE"] {
		t.Fatalf("%s as %s returned %+v, want a device collector bound to the tenant with its lane and the %s profile", surface, tn.slug, reg, tn.profile)
	}
	tn.collectorID, tn.lane, tn.hint = reg.AgentID, env["PROBECTL_DEVICE_BUS_NAMESPACE"], yaml
	t.Logf("%s registered device collector %s on lane %s (%s, %s profile)", tn.slug, tn.collectorID, tn.lane, surface, tn.profile)
}

func (tn *deviceTenant) registerAPI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var tok struct{ Token string }
	code, raw := st.Do(t, tn.cookie, http.MethodPost, "/v1/agents/enroll-tokens", map[string]any{"name": tn.sysName, "ttl_seconds": 600})
	if code != http.StatusCreated || json.Unmarshal(raw, &tok) != nil {
		t.Fatalf("POST /v1/agents/enroll-tokens as %s = %d: %.300s", tn.slug, code, raw)
	}
	var reg registration
	code, raw = st.Do(t, tn.cookie, http.MethodPost, "/v1/collectors/register", map[string]any{
		"token": tok.Token, "plane": "device", "hostname": tn.sysName, "collection_profile": tn.profile,
	})
	if code != http.StatusCreated || json.Unmarshal(raw, &reg) != nil {
		t.Fatalf("POST /v1/collectors/register as %s = %d: %.300s", tn.slug, code, raw)
	}
	tn.bind(t, "POST /v1/collectors/register", reg)
}

func (tn *deviceTenant) registerCLI(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var tok struct{ Token string }
	st.MustCLI(t, tn.env(), &tok, "agent", "enroll-token", "--body", fmt.Sprintf(`{"name":%q,"ttl_seconds":600}`, tn.sysName))
	var reg registration
	st.MustCLI(t, tn.env(), &reg, "collector", "register", "--body-file", st.SecretFile(t, map[string]any{
		"token": tok.Token, "plane": "device", "hostname": tn.sysName, "collection_profile": tn.profile,
	}))
	tn.bind(t, "probectl collector register", reg)
}

// startAgent runs the tenant's shipped device agent on the YAML its
// registration returned plus the operator's own device and trap stanzas. The
// credentials are named in the YAML and resolved from the environment; every
// secret field is a secret reference, never the value.
func (tn *deviceTenant) startAgent(t *testing.T, st *shipped.Stack, lab *snmpLab) {
	t.Helper()
	tn.trapListen, tn.trapSource = lab.trapEndpoint(t, tn.device)
	cfg := map[string]any{"apiVersion": "probectl.io/device-agent/v1"}
	for k, v := range tn.hint {
		cfg[k] = v
	}
	overrides := map[string]any{"interval": pollInterval.String()}
	if tn.profile != "topology-rich" {
		overrides["neighbors"] = true
	}
	cfg["devices"] = []map[string]any{{
		"address": "127.0.0.1", "port": tn.device.port, "transport": tn.transport,
		"credential": tn.credential, "collection_overrides": overrides,
	}}
	cfg["traps"] = map[string]any{
		"enabled": true, "listen": tn.trapListen,
		"sources": []map[string]any{{"name": tn.sysName, "address": tn.trapSource, "transport": tn.transport, "credential": tn.credential}},
	}
	raw, err := json.Marshal(cfg) // JSON is YAML
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(st.Dir, "device-agent-"+tn.slug+".yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cred := "PROBECTL_DEVICE_CRED_" + strings.ToUpper(strings.ReplaceAll(tn.credential, "-", "_")) + "_"
	secretVar := "PROBECTL_TEST_DEVICE_SECRET_" + strings.ToUpper(strings.ReplaceAll(tn.slug, "-", "_")) + "_"
	env := []string{
		"PROBECTL_DEVICE_BUS_MODE=kafka",
		"PROBECTL_DEVICE_BUS_BROKERS=" + strings.Join(testsupport.KafkaBrokers(), ","),
		"PROBECTL_DEVICE_BUS_ALLOW_PLAINTEXT=true", // the dev stack's Kafka is plaintext
		"PROBECTL_DEVICE_METRICS_ADDR=" + shipped.FreeAddr(t),
		"PROBECTL_DEVICE_LOG_LEVEL=debug",
	}
	switch tn.transport {
	case "snmpv3":
		env = append(env,
			cred+"USERNAME="+tn.user, cred+"AUTH_PROTO=sha", cred+"PRIV_PROTO=aes",
			cred+"AUTH_PASS=env:"+secretVar+"AUTH", cred+"PRIV_PASS=env:"+secretVar+"PRIV",
			secretVar+"AUTH="+tn.authPass, secretVar+"PRIV="+tn.privPass)
	default:
		env = append(env, cred+"COMMUNITY=env:"+secretVar+"COMMUNITY", secretVar+"COMMUNITY="+tn.community)
	}
	tn.agentLog = st.StartProcess(t, "device-agent-"+tn.slug, st.Binary(t, "probectl-device-agent"), []string{"-config", path}, env)
	shipped.Await(t, tn.slug+"'s device agent to start", 60*time.Second, func() bool {
		raw, _ := os.ReadFile(tn.agentLog)
		return strings.Contains(string(raw), `"device collector running"`)
	})
}

// --- device metrics ---

type metricSummary struct {
	ID         string    `json:"id"`
	Device     string    `json:"device"`
	DeviceName string    `json:"device_name"`
	AgentID    string    `json:"agent_id"`
	Source     string    `json:"source"`
	IfIndex    string    `json:"if_index"`
	IfName     string    `json:"if_name"`
	Metric     string    `json:"metric"`
	Value      float64   `json:"value"`
	LastSeen   time.Time `json:"last_seen"`
}

type metricList struct {
	Items          []metricSummary `json:"items"`
	MetricsRunning bool            `json:"metrics_running"`
	Source         string          `json:"source"`
}

func (tn *deviceTenant) metricsAPI(t *testing.T, st *shipped.Stack, query string) []metricSummary {
	t.Helper()
	var out metricList
	tn.get(t, st, "/v1/device/metrics?limit=500"+query, &out)
	if !out.MetricsRunning || out.Source != "tsdb" {
		t.Fatalf("GET /v1/device/metrics as %s says metrics_running=%v source=%q, want the TSDB read-back", tn.slug, out.MetricsRunning, out.Source)
	}
	return out.Items
}

func (tn *deviceTenant) metricsCLI(t *testing.T, st *shipped.Stack, query ...string) []metricSummary {
	t.Helper()
	args := []string{"device", "metrics", "--query", "limit=500"}
	for _, q := range query {
		args = append(args, "--query", q)
	}
	var out metricList
	tn.cli(t, st, &out, args...)
	return out.Items
}

// wantMetrics are the series every poll of a lab device must produce.
var wantMetrics = []string{"probectl_device_uptime_seconds", "probectl_device_if_oper_status",
	"probectl_device_if_in_octets", "probectl_device_if_out_octets"}

// complete reports whether items hold the tenant's device with every wanted
// metric and its eth0 counters.
func (tn *deviceTenant) complete(items []metricSummary) bool {
	have := map[string]bool{}
	for _, m := range items {
		if tn.owns(m) {
			have[m.Metric] = true
			if m.IfName == "eth0" {
				have["eth0:"+m.Metric] = true
			}
		}
	}
	for _, w := range wantMetrics {
		if !have[w] {
			return false
		}
	}
	return have["eth0:probectl_device_if_out_octets"]
}

// owns reports whether a sample is the tenant's own device, polled by its own
// agent over SNMP.
func (tn *deviceTenant) owns(m metricSummary) bool {
	return m.Device == "127.0.0.1" && m.DeviceName == tn.sysName && m.AgentID == tn.collectorID && m.Source == "snmp"
}

func (tn *deviceTenant) awaitMetrics(t *testing.T, st *shipped.Stack, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		items := tn.metricsAPI(t, st, "")
		if tn.complete(items) {
			t.Logf("%s sees %d live series of %s (agent %s) through GET /v1/device/metrics", tn.slug, len(items), tn.sysName, tn.collectorID)
			return
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(tn.agentLog)
			t.Fatalf("GET /v1/device/metrics as %s never listed %s's %v (+ eth0 counters); it lists %s\nagent log tail:\n%s",
				tn.slug, tn.sysName, wantMetrics, describeMetrics(items), tailLines(string(raw), 25))
		}
		time.Sleep(time.Second)
	}
}

// checkMetricSurfaces: the API and the CLI hold the tenant's device and
// nothing else, and the filters cannot reach the other tenant's.
func (tn *deviceTenant) checkMetricSurfaces(t *testing.T, st *shipped.Stack, tenants []*deviceTenant) {
	t.Helper()
	for surface, items := range map[string][]metricSummary{
		"GET /v1/device/metrics":                 tn.metricsAPI(t, st, ""),
		"probectl device metrics":                tn.metricsCLI(t, st),
		"GET /v1/device/metrics?device=":         tn.metricsAPI(t, st, "&device=127.0.0.1"),
		"probectl device metrics --query device": tn.metricsCLI(t, st, "device=127.0.0.1"),
	} {
		if !tn.complete(items) {
			t.Errorf("%s as %s misses %s's telemetry; it lists %s", surface, tn.slug, tn.sysName, describeMetrics(items))
		}
		for _, m := range items {
			if !tn.owns(m) {
				t.Errorf("%s as %s lists a series that is not its own device's: %s", surface, tn.slug, describeMetrics([]metricSummary{m}))
			}
		}
	}
	uptime := tn.metricsAPI(t, st, "&metric=uptime.seconds")
	if len(uptime) != 1 || !tn.owns(uptime[0]) || uptime[0].Metric != "probectl_device_uptime_seconds" || uptime[0].Value <= 0 {
		t.Errorf("GET /v1/device/metrics?metric=uptime.seconds as %s = %s, want exactly its own device's uptime", tn.slug, describeMetrics(uptime))
	}
	for _, other := range tenants {
		if other == tn {
			continue
		}
		for _, q := range []string{"&device=" + url.QueryEscape(other.sysName), "&device=" + url.QueryEscape(other.collectorID)} {
			if got := tn.metricsAPI(t, st, q); len(got) != 0 {
				t.Errorf("GET /v1/device/metrics?%s (%s's device) as %s lists %s", q[1:], other.slug, tn.slug, describeMetrics(got))
			}
		}
	}
}

// checkInventory: GET /v1/devices and `probectl device list` list the
// tenant's device under its own name, and not the other's.
func (tn *deviceTenant) checkInventory(t *testing.T, st *shipped.Stack, tenants []*deviceTenant) {
	t.Helper()
	type inventory struct {
		Items []struct {
			ID      string `json:"id"`
			Address string `json:"address"`
			Name    string `json:"name"`
		} `json:"items"`
		TopologyRunning bool `json:"topology_running"`
	}
	var api, cli inventory
	tn.get(t, st, "/v1/devices", &api)
	tn.cli(t, st, &cli, "device", "list")
	for surface, inv := range map[string]inventory{"GET /v1/devices": api, "probectl device list": cli} {
		found := false
		for _, d := range inv.Items {
			if d.Address == "127.0.0.1" && d.Name == tn.sysName {
				found = true
			}
			for _, other := range tenants {
				if other != tn && strings.Contains(d.Name+" "+d.ID, other.sysName) {
					t.Errorf("%s as %s lists %s's device: %+v", surface, tn.slug, other.slug, d)
				}
			}
		}
		if !inv.TopologyRunning || !found {
			t.Errorf("%s as %s = %+v, want its device 127.0.0.1 named %s", surface, tn.slug, inv, tn.sysName)
		}
	}
}

// outOctets is the eth0 out-octets sample of the tenant's device in items.
func (tn *deviceTenant) outOctets(items []metricSummary) (float64, bool) {
	for _, m := range items {
		if tn.owns(m) && m.IfName == "eth0" && m.Metric == "probectl_device_if_out_octets" {
			return m.Value, true
		}
	}
	return 0, false
}

// checkCounterMoves sends burstBytes out of the device's eth0 and waits for
// the API and the CLI to show its counter rise by at least that much, bounded
// by what the device's own kernel counted afterwards.
func (tn *deviceTenant) checkCounterMoves(t *testing.T, st *shipped.Stack) {
	t.Helper()
	const q = "&metric=if.out.octets"
	before, ok := tn.outOctets(tn.metricsAPI(t, st, q))
	if !ok {
		t.Fatalf("GET /v1/device/metrics%s as %s has no eth0 sample", q, tn.slug)
	}
	tn.device.burst(t)
	deadline := time.Now().Add(3*pollInterval + 30*time.Second)
	var after float64
	for {
		after, _ = tn.outOctets(tn.metricsAPI(t, st, q))
		if after-before >= burstBytes {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s's eth0 out-octets on GET /v1/device/metrics went %.0f -> %.0f after the device sent %d bytes: the poll does not reach the device's live counter",
				tn.slug, before, after, burstBytes)
		}
		time.Sleep(time.Second)
	}
	kernel := tn.device.txBytes(t)
	if after > kernel {
		t.Errorf("%s's eth0 out-octets on the API is %.0f, beyond the %.0f the device's kernel has counted", tn.slug, after, kernel)
	}
	cli, ok := tn.outOctets(tn.metricsCLI(t, st, "metric=if.out.octets"))
	if !ok || cli < before+burstBytes || cli > tn.device.txBytes(t) {
		t.Errorf("probectl device metrics as %s shows eth0 out-octets %.0f (ok=%v), want between %.0f and the device's own count", tn.slug, cli, ok, before+burstBytes)
	}
	tn.outOctetsLast = after
	t.Logf("%s's device sent %d bytes: eth0 out-octets %.0f -> %.0f on the API (device kernel: %.0f), %.0f on the CLI",
		tn.slug, burstBytes, before, after, kernel, cli)
}

// checkTSDBAttribution: in the TSDB each agent's series carry exactly its
// own tenant and device, and each tenant's series are exactly its own agent's.
// (Series of earlier runs stay queryable for the TSDB's lookback, so the
// receipt selects by this run's agent and tenant ids, never by device name.)
func checkTSDBAttribution(t *testing.T, tenants []*deviceTenant) {
	t.Helper()
	for _, tn := range tenants {
		byAgent := promSeries(t, `probectl_device_uptime_seconds{agent_id="`+tn.collectorID+`"}`)
		if len(byAgent) != 1 || byAgent[0]["tenant_id"] != tn.id || byAgent[0]["device_name"] != tn.sysName {
			t.Errorf("the TSDB holds agent %s's uptime as %v, want exactly one series of %s with tenant_id=%s", tn.collectorID, byAgent, tn.sysName, tn.id)
		}
		byTenant := promSeries(t, `probectl_device_uptime_seconds{tenant_id="`+tn.id+`"}`)
		if len(byTenant) != 1 || byTenant[0]["agent_id"] != tn.collectorID || byTenant[0]["device_name"] != tn.sysName {
			t.Errorf("the TSDB holds tenant %s's uptime series %v, want exactly %s's from agent %s", tn.slug, byTenant, tn.sysName, tn.collectorID)
		}
	}
}

// promSeries runs an instant query against the stack's Prometheus and returns
// the label sets of the result.
func promSeries(t *testing.T, query string) []map[string]string {
	t.Helper()
	base := os.Getenv("PROBECTL_PROM_URL")
	resp, err := http.Get(strings.TrimRight(base, "/") + "/api/v1/query?query=" + url.QueryEscape(query))
	if err != nil {
		t.Fatalf("query the TSDB: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode the TSDB answer to %s: %v", query, err)
	}
	labels := make([]map[string]string, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		labels = append(labels, r.Metric)
	}
	return labels
}

// --- physical adjacency and collection receipts ---

type neighborRow struct {
	AgentID            string `json:"agent_id"`
	LocalDeviceAddress string `json:"local_device_address"`
	LocalDeviceName    string `json:"local_device_name"`
	LocalPortID        string `json:"local_port_id"`
	RemoteDeviceName   string `json:"remote_device_name"`
	RemotePortID       string `json:"remote_port_id"`
	Protocol           string `json:"protocol"`
	Freshness          string `json:"freshness"`
}

type neighborList struct {
	Items             []neighborRow `json:"items"`
	CollectionRunning bool          `json:"collection_running"`
}

func (tn *deviceTenant) ownsNeighbor(n neighborRow) bool {
	return n.AgentID == tn.collectorID && n.LocalDeviceAddress == "127.0.0.1" && n.LocalDeviceName == tn.sysName &&
		n.RemoteDeviceName == tn.neighbor && n.RemotePortID == tn.neighborPort && n.Protocol == "lldp" &&
		n.LocalPortID == "eth0" && n.Freshness == "current"
}

func (tn *deviceTenant) awaitNeighbors(t *testing.T, st *shipped.Stack, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		var out neighborList
		tn.get(t, st, "/v1/device/neighbors?limit=500", &out)
		if slices.ContainsFunc(out.Items, tn.ownsNeighbor) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET /v1/device/neighbors as %s never listed %s on %s; it lists %+v", tn.slug, tn.neighbor, tn.neighborPort, out.Items)
		}
		time.Sleep(time.Second)
	}
}

func (tn *deviceTenant) checkNeighborSurfaces(t *testing.T, st *shipped.Stack, tenants []*deviceTenant) {
	t.Helper()
	var api, cli, filtered neighborList
	tn.get(t, st, "/v1/device/neighbors?limit=500", &api)
	tn.cli(t, st, &cli, "device", "neighbors", "--query", "limit=500")
	tn.get(t, st, "/v1/device/neighbors?protocol=lldp&device=127.0.0.1", &filtered)
	for surface, out := range map[string]neighborList{"GET /v1/device/neighbors": api, "probectl device neighbors": cli, "GET /v1/device/neighbors?protocol=lldp&device=127.0.0.1": filtered} {
		if !out.CollectionRunning || len(out.Items) != 1 || !tn.ownsNeighbor(out.Items[0]) {
			t.Errorf("%s as %s = %+v, want exactly %s's current LLDP neighbor %s on %s", surface, tn.slug, out, tn.sysName, tn.neighbor, tn.neighborPort)
		}
	}
	for _, other := range tenants {
		if other == tn {
			continue
		}
		var cross neighborList
		tn.get(t, st, "/v1/device/neighbors?device="+url.QueryEscape(other.sysName), &cross)
		if len(cross.Items) != 0 {
			t.Errorf("GET /v1/device/neighbors?device=%s as %s lists %+v", other.sysName, tn.slug, cross.Items)
		}
	}
}

type outcomeRow struct {
	AgentID          string `json:"agent_id"`
	ConfiguredTarget string `json:"configured_target"`
	Protocol         string `json:"protocol"`
	State            string `json:"state"`
	RowCount         int    `json:"row_count"`
}

func (tn *deviceTenant) checkOutcomeSurfaces(t *testing.T, st *shipped.Stack, tenants []*deviceTenant) {
	t.Helper()
	type outcomes struct {
		Items             []outcomeRow `json:"items"`
		CollectionRunning bool         `json:"collection_running"`
	}
	var api, cli outcomes
	tn.get(t, st, "/v1/device/collection-outcomes?limit=500", &api)
	tn.cli(t, st, &cli, "device", "outcomes", "--query", "limit=500")
	want := map[string]outcomeRow{
		"lldp": {AgentID: tn.collectorID, ConfiguredTarget: "127.0.0.1", Protocol: "lldp", State: "ok_with_rows", RowCount: 1},
		// net-snmp implements no CISCO-CDP-MIB. A GETBULK walk of an absent
		// table and of an empty one answer alike (the next OID lies outside
		// the subtree), so SNMP itself cannot say "unsupported" here: the
		// honest receipt is healthy_empty.
		"cdp": {AgentID: tn.collectorID, ConfiguredTarget: "127.0.0.1", Protocol: "cdp", State: "healthy_empty"},
	}
	for surface, out := range map[string]outcomes{"GET /v1/device/collection-outcomes": api, "probectl device outcomes": cli} {
		got := map[string]outcomeRow{}
		for _, o := range out.Items {
			got[o.Protocol] = o
		}
		if !out.CollectionRunning || len(out.Items) != 2 || got["lldp"] != want["lldp"] || got["cdp"] != want["cdp"] {
			t.Errorf("%s as %s = %+v, want exactly its own agent's receipts %+v", surface, tn.slug, out, want)
		}
	}
	for _, other := range tenants {
		if other == tn {
			continue
		}
		var cross outcomes
		tn.get(t, st, "/v1/device/collection-outcomes?agent_id="+url.QueryEscape(other.collectorID), &cross)
		if len(cross.Items) != 0 {
			t.Errorf("GET /v1/device/collection-outcomes?agent_id=%s (%s's agent) as %s lists %+v", other.collectorID, other.slug, tn.slug, cross.Items)
		}
	}
}

// rlsCounts counts a device table's rows as the app role every tenant read
// runs as, scoped to tenant by the per-transaction setting and with NO
// tenant_id predicate of its own, next to the tenant's own rows and every
// tenant's, counted as the privileged login.
func rlsCounts(t *testing.T, st *shipped.Stack, table, tenant string) (own, seen, total int) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, st.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	q := `SELECT count(*) FROM ` + pgx.Identifier{table}.Sanitize()
	if err := conn.QueryRow(ctx, q+` WHERE tenant_id = $1`, tenant).Scan(&own); err != nil {
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

// --- traps ---

// checkTraps sends each device's authenticated linkDown, plus two traps
// that must be refused, and asserts each tenant's trap-events lane holds
// exactly its own.
func checkTraps(t *testing.T, tenants []*deviceTenant) {
	t.Helper()
	A, B := tenants[0], tenants[1]
	for _, tn := range tenants {
		tn.device.trap(t, tn.trapListen, "")
	}
	// Refused: A's own device with the wrong auth passphrase, and B's device
	// (B's credential and address) sending to A's listener.
	A.device.trap(t, A.trapListen, "not-the-acme-passphrase")
	B.device.trap(t, A.trapListen, "")

	ids := map[string]bool{}
	for _, tn := range tenants {
		ids[tn.id], ids[tn.collectorID] = true, true
	}
	for _, tn := range tenants {
		topic, err := bus.TopicFor(tn.lane, bus.DeviceTrapEventsTopic)
		if err != nil {
			t.Fatal(err)
		}
		events := trapEvents(readLane(t, topic, 45*time.Second, func(recs [][]byte) bool {
			return slices.ContainsFunc(trapEvents(recs), tn.ownsTrap)
		}))
		var own []*devicev1.DeviceTrapEvent
		for _, e := range events {
			if !ids[e.GetTenantId()] && !ids[e.GetAgentId()] {
				continue // another run's lane cannot share this namespace, but be exact
			}
			if !tn.ownsTrap(e) {
				t.Errorf("%s's trap-events lane %s holds a trap that is not its device's: %s", tn.slug, topic, describeTrap(e))
				continue
			}
			own = append(own, e)
		}
		if len(own) != 1 {
			t.Errorf("%s's trap-events lane %s holds %d of its device's linkDown traps, want exactly 1: %v", tn.slug, topic, len(own), describeTraps(events))
		} else {
			t.Logf("%s's lane %s carries its device's %s linkDown from %s as %s (ifIndex %d), tenant %s agent %s",
				tn.slug, topic, own[0].GetVersion(), own[0].GetSourceAddress(), own[0].GetAuthPrincipal(), own[0].GetIfIndex(), own[0].GetTenantId(), own[0].GetAgentId())
		}
	}
	shared := trapEvents(readLane(t, bus.DeviceTrapEventsTopic, 5*time.Second, nil))
	for _, e := range shared {
		if ids[e.GetTenantId()] || ids[e.GetAgentId()] {
			t.Errorf("the shared trap-events lane holds this run's trap: %s", describeTrap(e))
		}
	}
	// The two refused traps reached A's listener and were counted as failed
	// ingest (payload-free), not silently lost on the way; B's saw none.
	for _, tn := range tenants {
		want := map[*deviceTenant]uint64{A: 2, B: 0}[tn]
		var got uint64
		shipped.Await(t, fmt.Sprintf("%s's trap listener to count %d refused traps", tn.slug, want), 30*time.Second, func() bool {
			got = refusedTraps(t, tn.agentLog)
			return got == want
		})
		t.Logf("%s's trap listener refused %d trap(s)", tn.slug, got)
	}
}

// refusedTraps sums the trap listener's failure counters from the agent's log
// (the newest failures_total of each error class).
func refusedTraps(t *testing.T, logPath string) uint64 {
	t.Helper()
	raw, _ := os.ReadFile(logPath)
	latest := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		var rec struct {
			Msg      string `json:"msg"`
			Listener string `json:"listener"`
			Class    string `json:"error_class"`
			Total    uint64 `json:"failures_total"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.Msg != "live ingestion record failed" || rec.Listener != "snmp_trap" {
			continue
		}
		latest[rec.Class] = max(latest[rec.Class], rec.Total)
	}
	var sum uint64
	for _, n := range latest {
		sum += n
	}
	return sum
}

func (tn *deviceTenant) ownsTrap(e *devicev1.DeviceTrapEvent) bool {
	principal := tn.sysName
	if tn.transport == "snmpv3" {
		principal = tn.user
	}
	return e.GetTenantId() == tn.id && e.GetAgentId() == tn.collectorID && e.GetKind() == "snmp.trap.link_down" &&
		e.GetAuthPrincipal() == principal && e.GetVersion() == tn.transport && e.GetIfIndex() == tn.device.eth0 &&
		e.GetSourceAddress() == tn.trapSource && e.GetDeviceAddress() == tn.trapSource
}

func trapEvents(recs [][]byte) []*devicev1.DeviceTrapEvent {
	var out []*devicev1.DeviceTrapEvent
	for _, r := range recs {
		var batch devicev1.DeviceTrapEventBatch
		if proto.Unmarshal(r, &batch) == nil {
			out = append(out, batch.GetEvents()...)
		}
	}
	return out
}

func describeTrap(e *devicev1.DeviceTrapEvent) string {
	return fmt.Sprintf("%s %s from %s as %s ifIndex=%d tenant=%s agent=%s", e.GetVersion(), e.GetKind(), e.GetSourceAddress(),
		e.GetAuthPrincipal(), e.GetIfIndex(), e.GetTenantId(), e.GetAgentId())
}

func describeTraps(events []*devicev1.DeviceTrapEvent) string {
	parts := make([]string, 0, len(events))
	for _, e := range events {
		parts = append(parts, describeTrap(e))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

// readLane reads a topic from its start in a fresh consumer group until done
// holds (nil: for the whole window) or the window ends, and returns every
// record value it saw.
func readLane(t *testing.T, topic string, within time.Duration, done func([][]byte) bool) [][]byte {
	t.Helper()
	b, err := bus.New("kafka", testsupport.KafkaBrokers(), bus.Security{AllowPlaintext: true})
	if err != nil {
		t.Fatalf("open the bus: %v", err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	var mu sync.Mutex
	var recs [][]byte
	group := "f18-receipt-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	go func() {
		_ = b.Subscribe(ctx, topic, group, func(_ context.Context, msg bus.Message) error {
			mu.Lock()
			recs = append(recs, append([]byte(nil), msg.Value...))
			mu.Unlock()
			return nil
		})
	}()
	for ctx.Err() == nil {
		mu.Lock()
		ok := done != nil && done(recs)
		mu.Unlock()
		if ok {
			// Let the rest of the lane arrive before judging what else it holds.
			time.Sleep(2 * time.Second)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	return append([][]byte(nil), recs...)
}

// --- the rendered page ---

func (tn *deviceTenant) renderPage(t *testing.T, st *shipped.Stack, tenants []*deviceTenant) {
	t.Helper()
	page := testsupport.RenderSpec{
		URL:            st.BaseURL + "/ui/planes/device",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: tn.cookie}},
		TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile,
		Expect: []string{tn.sysName, "device:127.0.0.1", tn.neighbor, tn.neighborPort, "LLDP",
			"Device telemetry", "Device health samples", "Interface counters", "probectl_device_*", "eth0"},
	}
	for _, other := range tenants {
		if other != tn {
			page.Absent = append(page.Absent, other.sysName, other.neighbor, other.neighborPort, other.collectorID)
		}
	}
	res := testsupport.RenderUI(t, page)
	tn.keep([]byte(res.Text))
	// The page shows the live counter: eth0's out-octets as rendered is at
	// least what the API showed after the burst, and no more than the
	// device's kernel has counted.
	m := renderedOutOctets.FindStringSubmatch(res.Text)
	if m == nil {
		t.Fatalf("the rendered Device page as %s shows no eth0 out-octets row:\n%s", tn.slug, res.Text)
	}
	shown, err := strconv.ParseFloat(strings.NewReplacer(",", "", "\u00a0", "", " ", "").Replace(m[1]), 64)
	if err != nil {
		t.Fatalf("the rendered eth0 out-octets %q as %s: %v", m[1], tn.slug, err)
	}
	if kernel := tn.device.txBytes(t); shown < tn.outOctetsLast || shown > kernel {
		t.Errorf("the rendered Device page as %s shows eth0 out-octets %.0f, want between %.0f (the API after the burst) and %.0f (the device's own count)",
			tn.slug, shown, tn.outOctetsLast, kernel)
	} else {
		t.Logf("the rendered Device page shows %s its eth0 out-octets %.0f (API after the burst: %.0f)", tn.slug, shown, tn.outOctetsLast)
	}
}

// renderedOutOctets finds eth0's row in the Device telemetry card's
// interface table, in the page's text: interface, status, speed, octets in,
// octets out.
var renderedOutOctets = regexp.MustCompile(`eth0\s+(?:up|down)\s+(?:[0-9][0-9,]*\s+Mbps|Not reported)\s+(?:[0-9][0-9,]*|Not reported)\s+([0-9][0-9,]*)`)

// --- secrets ---

// checkNoSecrets byte-searches every place a credential could leak: the
// control plane's and both agents' logs, every API and CLI body and rendered
// page this receipt saw, and every record on both tenants' device lanes.
func checkNoSecrets(t *testing.T, st *shipped.Stack, tenants []*deviceTenant) {
	t.Helper()
	var all []string
	for _, tn := range tenants {
		all = append(all, tn.secrets()...)
	}
	logs, _ := filepath.Glob(filepath.Join(st.Dir, "*.log"))
	for _, l := range logs {
		raw, _ := os.ReadFile(l)
		for _, s := range all {
			if bytes.Contains(raw, []byte(s)) {
				t.Errorf("%s holds a device credential (%d chars)", filepath.Base(l), len(s))
			}
		}
	}
	for _, tn := range tenants {
		for _, raw := range tn.seen {
			for _, s := range all {
				if bytes.Contains(raw, []byte(s)) {
					t.Errorf("a response or page served to %s holds a device credential (%d chars)", tn.slug, len(s))
				}
			}
		}
		n := 0
		for _, base := range []string{bus.DeviceMetricsTopic, bus.DeviceNeighborsTopic, bus.DeviceCollectionOutcomesTopic, bus.DeviceTrapEventsTopic} {
			topic, err := bus.TopicFor(tn.lane, base)
			if err != nil {
				t.Fatal(err)
			}
			recs := readLane(t, topic, 8*time.Second, nil)
			n += len(recs)
			for _, r := range recs {
				for _, s := range all {
					if bytes.Contains(r, []byte(s)) {
						t.Errorf("a record on %s holds a device credential (%d chars)", topic, len(s))
					}
				}
			}
		}
		if n == 0 {
			t.Errorf("%s's device lanes hold no records to search", tn.slug)
		}
		t.Logf("no device credential in %d log files, %d responses/pages served to %s, or %d records on its device lanes",
			len(logs), len(tn.seen), tn.slug, n)
	}
}

// --- the SNMP lab ---

// snmpLab is one net-snmp snmpd container per tenant, plus the host side the
// devices reach: the agents' trap listeners and the sink their traffic
// bursts go to.
type snmpLab struct {
	name, image string
	// listenIP is the host address the devices can reach (macOS: loopback,
	// which Docker Desktop forwards host.docker.internal to; Linux: the
	// docker bridge's gateway). dialHost is how a device names it.
	listenIP, dialHost string
}

// snmpDevice is one lab device: a running snmpd and its loopback port.
type snmpDevice struct {
	lab       *snmpLab
	container string
	port      int
	ip        string // the container's address on the docker bridge
	eth0      uint32 // eth0's ifIndex on the device
	engineID  string // the SNMPv3 engine id its traps carry
}

func startSNMPLab(t *testing.T) *snmpLab {
	t.Helper()
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		testsupport.SkipOrFatal(t, "the device receipt runs real SNMP agents in docker: %v %s", err, out)
	}
	lab := &snmpLab{name: os.Getenv("PROBECTL_TEST_DEVICE_LAB_NAME"), image: "probectl-it-snmpd:alpine-3.22.6"}
	if lab.name == "" {
		lab.name = "probectl-it-device-" + strconv.FormatInt(time.Now().UnixNano()%1e8, 36)
	}
	dockerfile := "FROM " + snmpdBase + "\nRUN apk add --no-cache net-snmp net-snmp-tools\n"
	var out []byte
	var err error
	for attempt := 0; attempt < 3; attempt++ { // registry pulls fail transiently
		cmd := exec.Command("docker", "build", "-q", "-t", lab.image, "-")
		cmd.Stdin = strings.NewReader(dockerfile)
		if out, err = cmd.CombinedOutput(); err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		t.Fatalf("build the lab's snmpd image from %s: %v\n%s", snmpdBase, err, out)
	}
	if runtime.GOOS == "darwin" {
		lab.listenIP, lab.dialHost = "127.0.0.1", "host.docker.internal"
	} else {
		gw := strings.TrimSpace(lab.docker(t, "network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"))
		if net.ParseIP(gw) == nil {
			t.Fatalf("the docker bridge has no gateway address (%q) for the devices to reach the host on", gw)
		}
		lab.listenIP, lab.dialHost = gw, gw
	}
	version, _ := exec.Command("docker", "run", "--rm", lab.image, "sh", "-c", "apk info -v 2>/dev/null | grep '^net-snmp-[0-9]'").Output()
	t.Logf("SNMP lab %s: %s snmpd on %s; devices reach the host at %s", lab.name, strings.TrimSpace(string(version)), snmpdBase, lab.dialHost)
	return lab
}

func (lab *snmpLab) docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		// The argv can carry a lab credential (snmptrap -A); name the verb only.
		t.Fatalf("docker %s: %v\n%s", args[0], err, out)
	}
	return string(out)
}

// startDevice starts the tenant's SNMP agent with its identity, its
// credential and its LLDP neighbor, plus the net-snmp client config its traps
// are sent with.
func (lab *snmpLab) startDevice(t *testing.T, tn *deviceTenant) *snmpDevice {
	t.Helper()
	short := strings.SplitN(tn.sysName, "-", 2)[0]
	d := &snmpDevice{lab: lab, container: lab.name + "-snmpd-" + short}
	_ = exec.Command("docker", "rm", "-f", d.container).Run()
	lab.docker(t, "create", "--name", d.container, "-p", "127.0.0.1::161/udp", lab.image,
		"snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf", "udp:161")
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "15", d.container).CombinedOutput()
			t.Logf("snmpd %s log tail:\n%s", d.container, out)
		}
		_ = exec.Command("docker", "rm", "-f", d.container).Run()
	})
	var agent, client strings.Builder
	switch tn.transport {
	case "snmpv3":
		d.engineID = "0x80001f8803a1b2c3d4" + map[string]string{"acme": "01", "globex": "02"}[short]
		fmt.Fprintf(&agent, "createUser %s SHA %q AES %q\nrouser %s priv\n", tn.user, tn.authPass, tn.privPass, tn.user)
		fmt.Fprintf(&client, "defVersion 3\ndefSecurityName %s\ndefSecurityLevel authPriv\ndefAuthType SHA\ndefAuthPassphrase %s\ndefPrivType AES\ndefPrivPassphrase %s\n",
			tn.user, tn.authPass, tn.privPass)
	default:
		fmt.Fprintf(&agent, "rocommunity %s\n", tn.community)
		fmt.Fprintf(&client, "defVersion 2c\ndefCommunity %s\n", tn.community)
	}
	fmt.Fprintf(&agent, "sysName %s\nsysLocation %s lab\nsysContact noc@%s.example\n", tn.sysName, tn.name, short)
	// LLDP-MIB: the local port (lldpLocPortNum 2, eth0) and one remote system
	// learned on it (lldpRemTimeMark 0, lldpRemLocalPortNum 2, lldpRemIndex 1),
	// served by snmpd itself.
	for _, row := range [][2]string{
		{".1.0.8802.1.1.2.1.3.7.1.2.2", "integer 5"}, // lldpLocPortIdSubtype: interfaceName
		{".1.0.8802.1.1.2.1.3.7.1.3.2", `octet_str "eth0"`},
		{".1.0.8802.1.1.2.1.3.7.1.4.2", `octet_str "uplink"`},
		{".1.0.8802.1.1.2.1.4.1.1.4.0.2.1", "integer 4"}, // lldpRemChassisIdSubtype: macAddress
		{".1.0.8802.1.1.2.1.4.1.1.5.0.2.1", `octet_str "02:42:ac:11:00:99"`},
		{".1.0.8802.1.1.2.1.4.1.1.6.0.2.1", "integer 5"}, // lldpRemPortIdSubtype: interfaceName
		{".1.0.8802.1.1.2.1.4.1.1.7.0.2.1", fmt.Sprintf("octet_str %q", tn.neighborPort)},
		{".1.0.8802.1.1.2.1.4.1.1.8.0.2.1", `octet_str "uplink"`},
		{".1.0.8802.1.1.2.1.4.1.1.9.0.2.1", fmt.Sprintf("octet_str %q", tn.neighbor)},
		{".1.0.8802.1.1.2.1.4.1.1.10.0.2.1", fmt.Sprintf("octet_str %q", tn.name+" lab neighbor")},
	} {
		fmt.Fprintf(&agent, "override %s %s\n", row[0], row[1])
	}
	dir := t.TempDir()
	for name, body := range map[string]string{"snmpd.conf": agent.String(), "snmp.conf": client.String()} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		lab.docker(t, "cp", p, d.container+":/etc/snmp/"+name)
	}
	lab.docker(t, "start", d.container)
	shipped.Await(t, d.container+"'s snmpd to answer", 30*time.Second, func() bool {
		out, err := exec.Command("docker", "exec", d.container, "snmpget", "-t", "1", "-r", "0", "-Ovq", "127.0.0.1", "SNMPv2-MIB::sysName.0").Output()
		return err == nil && strings.TrimSpace(string(out)) == tn.sysName
	})
	hostPort := strings.TrimSpace(lab.docker(t, "port", d.container, "161/udp"))
	for _, line := range strings.Split(hostPort, "\n") {
		if p, ok := strings.CutPrefix(line, "127.0.0.1:"); ok {
			d.port, _ = strconv.Atoi(p)
		}
	}
	if d.port == 0 {
		t.Fatalf("docker port %s 161/udp = %q, want a 127.0.0.1 binding", d.container, hostPort)
	}
	idx, err := strconv.ParseUint(strings.TrimSpace(lab.docker(t, "exec", d.container, "cat", "/sys/class/net/eth0/ifindex")), 10, 32)
	if err != nil {
		t.Fatalf("eth0's ifIndex on %s: %v", d.container, err)
	}
	d.eth0 = uint32(idx)
	d.ip = strings.TrimSpace(lab.docker(t, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", d.container))
	t.Logf("device %s (%s, %s) answers on 127.0.0.1:%d; eth0 is ifIndex %d", tn.sysName, d.container, tn.transport, d.port, d.eth0)
	return d
}

// trapEndpoint picks the tenant agent's trap listener and the source address
// its device's traps arrive from.
func (lab *snmpLab) trapEndpoint(t *testing.T, d *snmpDevice) (listen, source string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(lab.listenIP, "0"))
	if err != nil {
		t.Fatalf("a UDP port on %s for the trap listener: %v", lab.listenIP, err)
	}
	listen = pc.LocalAddr().String()
	_ = pc.Close()
	if runtime.GOOS == "darwin" {
		return listen, "127.0.0.1" // Docker Desktop delivers it from loopback
	}
	return listen, d.ip
}

// trap sends one linkDown for eth0 from the device to listen with net-snmp's
// snmptrap and the device's own client credential; wrongAuth replaces the
// SNMPv3 auth passphrase.
func (d *snmpDevice) trap(t *testing.T, listen, wrongAuth string) {
	t.Helper()
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"exec", d.container, "snmptrap"}
	if d.engineID != "" {
		args = append(args, "-e", d.engineID)
	}
	if wrongAuth != "" {
		args = append(args, "-A", wrongAuth)
	}
	// agent, uptime ("" = now), the trap OID (linkDown), then ifIndex.<eth0>.
	eth0 := strconv.FormatUint(uint64(d.eth0), 10)
	args = append(args, net.JoinHostPort(d.lab.dialHost, port), "", ".1.3.6.1.6.3.1.1.5.3", ".1.3.6.1.2.1.2.2.1.1."+eth0, "i", eth0)
	d.lab.docker(t, args...)
}

// burst sends burstBytes out of the device's eth0 to a sink on the host.
func (d *snmpDevice) burst(t *testing.T) {
	t.Helper()
	sink, err := net.ListenPacket("udp", net.JoinHostPort(d.lab.listenIP, "0"))
	if err != nil {
		t.Fatalf("the traffic sink: %v", err)
	}
	defer sink.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		buf := make([]byte, 65536)
		for ctx.Err() == nil {
			_ = sink.SetReadDeadline(time.Now().Add(time.Second))
			_, _, _ = sink.ReadFrom(buf)
		}
	}()
	_, port, _ := net.SplitHostPort(sink.LocalAddr().String())
	cmd := fmt.Sprintf("dd if=/dev/zero bs=1400 count=%d 2>/dev/null | nc -u -w1 %s %s", burstBytes/1400, d.lab.dialHost, port)
	before := d.txBytes(t)
	d.lab.docker(t, "exec", d.container, "sh", "-c", cmd)
	if sent := d.txBytes(t) - before; sent < burstBytes {
		t.Fatalf("%s sent only %.0f bytes out of eth0 for the %d-byte burst", d.container, sent, burstBytes)
	}
}

// txBytes is what the device's kernel has counted out of eth0.
func (d *snmpDevice) txBytes(t *testing.T) float64 {
	t.Helper()
	n, err := strconv.ParseFloat(strings.TrimSpace(d.lab.docker(t, "exec", d.container, "cat", "/sys/class/net/eth0/statistics/tx_bytes")), 64)
	if err != nil {
		t.Fatalf("eth0 tx_bytes on %s: %v", d.container, err)
	}
	return n
}

// --- helpers ---

func describeMetrics(items []metricSummary) string {
	parts := make([]string, 0, len(items))
	for i, m := range items {
		if i == 12 {
			parts = append(parts, fmt.Sprintf("... %d more", len(items)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("%s{device=%s name=%s agent=%s if=%s}=%.0f", m.Metric, m.Device, m.DeviceName, m.AgentID, m.IfName, m.Value))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
