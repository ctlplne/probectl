// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type dependencyPhysicalNetwork struct {
	source, router, child, other string
}

type dependencyPhysicalLane struct {
	tenant      string
	network     dependencyPhysicalNetwork
	definitions []testspec.ExecutableDefinition
	client      *agent.EvidenceClient
	relay       *testsupport.SMTPServer
	mail        alert.MailSender
	evaluator   *alert.Evaluator
}

func TestDependencyRouterPhysicalFailureRecoveryAndTenantIsolation(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB", "isolated routed Linux networks; existing CI runs this root explicitly")
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("the required physical router lab needs namespace privileges")
	}
	for _, tool := range []string{"ip", "tc", "sysctl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal("required router lab tool is unavailable", tool, err)
		}
	}
	d := seedDependencyRoutingFixture(t)
	transport := startDependencyPhysicalTransport(t, d)
	writer, err := tsdb.New("memory", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	socket := httptest.NewTLSServer(d.f.server.Handler())
	t.Cleanup(socket.Close)
	build := func(lane *dependencyPhysicalLane) *alert.Evaluator {
		t.Helper()
		sink := AlertSink(BuildCorrelator(d.f.pool, 5*time.Minute, d.f.server.log), d.f.server.log)
		evaluator, ok := BuildAlertEvaluator(d.f.pool, writer, alert.ChannelDeps{Mail: lane.mail}, time.Second, tenancy.ID(lane.tenant), sink, d.f.server.log,
			AlertTagDependencies{Gate: d.f.server.fairnessGate, FlowStore: d.f.server.flowStore, Queries: d.f.server})
		if !ok {
			t.Fatal("shipping physical evaluator is unavailable")
		}
		return evaluator
	}
	evaluate := func(lane *dependencyPhysicalLane) {
		t.Helper()
		if _, err := lane.evaluator.Engine().Evaluate(tenancy.WithTenant(t.Context(), tenancy.ID(lane.tenant)), *d.rules[lane.tenant]); err != nil {
			t.Fatal("physical alert evaluation failed", err)
		}
	}
	sample := func(lane *dependencyPhysicalLane) []dependencyPhysicalMeasurement {
		t.Helper()
		measurements := sampleDependencyPhysical(t, d, lane.tenant, lane.network.source, lane.definitions, lane.client, writer)
		evaluate(lane)
		return measurements
	}
	var lanes []*dependencyPhysicalLane
	for _, tenant := range d.f.tenants {
		lane := &dependencyPhysicalLane{tenant: tenant, network: newDependencyPhysicalNetwork(t)}
		lane.client = transport.sender(t, d, tenant)
		lane.definitions = dependencyPhysicalDefinitions(t, d, tenant)
		lane.relay, lane.mail = transport.mail(t)
		lane.evaluator = build(lane)
		lanes = append(lanes, lane)
		baseline := sample(lane)
		for i, measurement := range baseline {
			if !measurement.Result.Success {
				for _, args := range [][]string{{"-n", lane.network.source, "route", "get", lane.definitions[i].Target}, {"-n", lane.network.router, "route", "show"}} {
					out, err := exec.CommandContext(t.Context(), "ip", args...).CombinedOutput()
					t.Logf("owned physical baseline route: %s; error=%v", out, err)
				}
				t.Fatalf("healthy physical collector target %s failed: error=%q measurement=%+v", lane.definitions[i].Target, measurement.Result.Error, measurement.Measurement)
			}
		}
		if len(lane.relay.Messages()) != 0 || len(lane.evaluator.Engine().Active()) != 0 {
			t.Fatalf("healthy physical network emitted an alert: messages=%d active=%+v baseline=%+v", len(lane.relay.Messages()), lane.evaluator.Engine().Active(), baseline)
		}
	}
	for laneIndex, lane := range lanes {
		t.Logf("physical tenant lane %d", laneIndex)
		n := lane.network
		dependencyPhysicalLoss(t, n.router, "to-source", true)
		sample(lane)
		if len(lane.relay.Messages()) != 1 || len(lane.evaluator.Engine().Active()) != 2 {
			t.Fatal("real upstream outage did not yield exactly one notification and two active alerts", len(lane.relay.Messages()))
		}
		parent := assertDependencyPhysicalParent(t, d, lane.tenant, "held")
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(d.f.tokens[lane.tenant]))
		room, err := client.GetIncident(t.Context(), sdk.GetIncidentRequest{Id: parent})
		if err != nil || room == nil || room.TenantId != lane.tenant || room.SignalCount != 2 || len(room.Signals) != 2 {
			t.Fatal("verified HTTPS incident room hid the physical downstream alert", room, err)
		}
		lane.evaluator = build(lane)
		evaluate(lane)
		if len(lane.relay.Messages()) != 1 {
			t.Fatal("leader restart repeated a held physical notification")
		}
		dependencyPhysicalLoss(t, n.other, "to-source", true)
		sample(lane)
		if len(lane.relay.Messages()) != 2 {
			t.Fatal("an independent physical downstream fault failed to notify")
		}
		dependencyPhysicalLoss(t, n.child, "to-router", true)
		dependencyPhysicalLoss(t, n.router, "to-source", false)
		sample(lane)
		if len(lane.relay.Messages()) != 4 || len(lane.evaluator.Engine().Active()) != 2 {
			t.Fatal("upstream recovery lost its resolution or the persistent child's first notification", len(lane.relay.Messages()))
		}
		if assertDependencyPhysicalParent(t, d, lane.tenant, "released") != parent {
			t.Fatal("physical recovery detached the original visible child history")
		}
		evaluate(lane)
		if len(lane.relay.Messages()) != 4 {
			t.Fatal("persistent physical downstream fault was released more than once")
		}
		for _, message := range lane.relay.Messages() {
			if !message.TLS {
				t.Fatal("physical notification escaped TLS SMTP")
			}
		}
		peer := lanes[1-laneIndex]
		before := len(peer.relay.Messages())
		evaluate(peer)
		if len(peer.relay.Messages()) != before {
			t.Fatal("overlapping-address tenant borrowed the other's physical transition")
		}
	}
	t.Log("real-integration: two isolated routed Linux networks, compiled ICMP collectors, issued mTLS evidence RPC, app-role PG/RLS, lightweight TSDB, shipping evaluator/correlator, verified HTTPS incident room and TLS SMTP; packets and deliveries are real, production image qualification remains separate")
}

func assertDependencyPhysicalParent(t *testing.T, d *dependencyRoutingFixture, tenant, state string) string {
	t.Helper()
	var parent string
	d.f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var roots int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),COALESCE(min(id::text),'') FROM incidents
			WHERE tenant_id=$1 AND entity_context_id=$2 AND entity_id=$3 AND identity_lookup_attempted`,
			tenant, d.f.contextID, d.graphs[tenant].Nodes[0].EntityID).Scan(&roots, &parent); err != nil {
			return err
		}
		if roots != 1 {
			t.Fatal("physical source did not retain one canonical upstream case", roots)
		}
		var children int
		err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals WHERE tenant_id=$1 AND incident_id=$2
			AND entity_context_id=$3 AND entity_id=$4 AND identity_lookup_attempted AND attributes->>'dependency.state'=$5`,
			tenant, parent, d.f.contextID, d.graphs[tenant].Nodes[1].EntityID, state).Scan(&children)
		if err == nil && children != 1 {
			t.Fatal("physical child was absent or duplicated on its upstream timeline", state, children)
		}
		return err
	})
	return parent
}

func dependencyLabCommand(t *testing.T, command string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, command, args...).CombinedOutput(); err != nil {
		t.Fatalf("owned dependency lab command %s %v: %v: %s", command, args, err, out)
	}
}

func newDependencyPhysicalNetwork(t *testing.T) dependencyPhysicalNetwork {
	t.Helper()
	prefix := "probectl-qa-beta-dep-" + gouuid.NewString()[:8]
	n := dependencyPhysicalNetwork{prefix + "-source", prefix + "-router", prefix + "-child", prefix + "-other"}
	names := []string{n.source, n.router, n.child, n.other}
	for _, name := range names {
		dependencyLabCommand(t, "ip", "netns", "add", name)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, "ip", "netns", "del", name).CombinedOutput(); err != nil {
				t.Errorf("remove owned dependency namespace %s: %v: %s", name, err, out)
			}
		})
		dependencyLabCommand(t, "ip", "-n", name, "link", "set", "lo", "up")
	}
	link := func(left, leftDev, leftIP, right, rightDev, rightIP string) {
		t.Helper()
		dependencyLabCommand(t, "ip", "-n", left, "link", "add", leftDev, "type", "veth", "peer", "name", rightDev, "netns", right)
		for _, end := range []struct{ ns, dev, ip string }{{left, leftDev, leftIP}, {right, rightDev, rightIP}} {
			dependencyLabCommand(t, "ip", "-n", end.ns, "addr", "add", end.ip, "dev", end.dev)
			dependencyLabCommand(t, "ip", "-n", end.ns, "link", "set", end.dev, "up")
		}
	}
	link(n.source, "to-router", "10.250.0.2/30", n.router, "to-source", "10.250.0.1/30")
	link(n.router, "to-child", "10.250.1.1/30", n.child, "to-router", "10.250.1.2/30")
	link(n.source, "to-other", "10.250.2.1/30", n.other, "to-source", "10.250.2.2/30")
	for _, end := range []struct{ ns, address string }{{n.router, "192.0.2.1/32"}, {n.child, "192.0.2.2/32"}, {n.other, "192.0.2.3/32"}} {
		dependencyLabCommand(t, "ip", "-n", end.ns, "addr", "add", end.address, "dev", "lo")
	}
	dependencyLabCommand(t, "ip", "netns", "exec", n.router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	for _, route := range []struct{ ns, prefix, via string }{
		{n.source, "192.0.2.0/24", "10.250.0.1"},
		{n.source, "192.0.2.3/32", "10.250.2.2"},
		{n.router, "192.0.2.2/32", "10.250.1.2"},
		{n.child, "default", "10.250.1.1"},
		{n.other, "default", "10.250.2.1"},
	} {
		dependencyLabCommand(t, "ip", "-n", route.ns, "route", "add", route.prefix, "via", route.via)
	}
	return n
}

func dependencyPhysicalLoss(t *testing.T, ns, dev string, down bool) {
	t.Helper()
	args := []string{"netns", "exec", ns, "tc", "qdisc"}
	if down {
		args = append(args, "add", "dev", dev, "root", "netem", "loss", "100%")
	} else {
		args = append(args, "del", "dev", dev, "root")
	}
	dependencyLabCommand(t, "ip", args...)
}

type dependencyPhysicalMeasurement struct {
	Result      canary.Result
	Measurement *canary.ICMPMeasurement
}

// The same compiled-in collector runs in the source namespace. Its IO facts
// are returned intact; no test substitutes a loss flag or fabricated responder.
func TestDependencyPhysicalProbeProcess(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_DEPENDENCY_PROBE_CHILD") != "1" {
		return
	}
	var definition testspec.ExecutableDefinition
	if err := json.Unmarshal([]byte(os.Getenv("PROBECTL_TEST_DEPENDENCY_PROBE_DEFINITION")), &definition); err != nil {
		t.Fatal(err)
	}
	probe, err := canary.NewICMP(canary.Config{Type: definition.Type, Target: definition.Target,
		Interval: time.Duration(definition.IntervalSeconds) * time.Second, Timeout: time.Duration(definition.TimeoutSeconds) * time.Second, Params: definition.Params})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.Run(t.Context())
	if err != nil || result.ICMP == nil || !result.ICMP.Complete() {
		t.Fatal("physical source did not retain complete collector IO", err, result.Error, result.ICMP)
	}
	body, err := json.Marshal(dependencyPhysicalMeasurement{Result: result, Measurement: result.ICMP})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("PROBECTL_TEST_DEPENDENCY_PROBE_OUTPUT"), body, 0600); err != nil {
		t.Fatal(err)
	}
}

func collectDependencyPhysical(t *testing.T, ns string, definition testspec.ExecutableDefinition) dependencyPhysicalMeasurement {
	t.Helper()
	body, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "measurement.json")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestDependencyPhysicalProbeProcess$")
	cmd.Env = append(os.Environ(), "PROBECTL_TEST_DEPENDENCY_PROBE_CHILD=1", "PROBECTL_TEST_DEPENDENCY_PROBE_DEFINITION="+string(body), "PROBECTL_TEST_DEPENDENCY_PROBE_OUTPUT="+output)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("physical ICMP child: %v: %s", err, out)
	}
	body, err = os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var value dependencyPhysicalMeasurement
	if err := json.Unmarshal(body, &value); err != nil || value.Measurement == nil || !value.Measurement.Complete() {
		t.Fatal("physical collector result was not complete", err)
	}
	return value
}
