// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
	"github.com/ctlplne/probectl/internal/topology"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// The paired lanes share context, device, failed interface and exporter IDs.
// Independent ClickHouse populations distinguish the tenants.
// First test raw rows without original captures. Then exercise the same
// served path with recorded versions of both BGP exits and counter polls.
func TestTopologyFailurePairedSourcesOnTLSAndNativeMCP(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if endpoint == "" {
		testsupport.SkipOrFatal(t, "topology failure paired proof requires PROBECTL_FLOWSTORE_URL")
	}
	f, _, _, _ := newRoleFlowQueryFixture(t)
	ch, err := flowstore.NewClickHouse(endpoint, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	readerUser, reader := chtest.ProvisionReader(t, endpoint, "fx11_traffic_reader")
	ch.WithTenantScoping(true).WithReader(reader)
	if err := ch.EnsureReaderRowPolicy(t.Context(), readerUser); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, tenant := range f.tenants {
			if _, err := ch.DeleteTenant(ctx, tenant); err != nil {
				t.Error(err)
			}
		}
	})
	graph := topology.NewMemoryStore()
	f.server.WithTopology(graph).WithFlowStore(ch).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	seedInterfaceRoleMCPConsent(f)
	const local, remote = "192.0.2.1", "192.0.2.2"
	const target = "device:" + local + "|physical|device:" + remote
	to := time.Now().UTC().Truncate(time.Minute)
	from := to.Add(-time.Minute)
	sharedNeighborGeneration := pathHealthTestID(t)
	for lane, tenant := range f.tenants {
		seedTopologyFailureLink(t, f, graph, tenant, local, remote)
		seedTopologyFailureNeighborViews(t, f, tenant, sharedNeighborGeneration, 64496+uint32(lane))
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		var rows []flowstore.Row
		for i := range lane + 1 {
			rows = append(rows, flowstore.Row{TenantID: tenant, AgentID: "role-flow", Exporter: local, Protocol: "ipfix",
				ObsDomain: 4294967295, OutIf: 7, SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", NextHop: remote,
				StartTS: to.Add(-5 * time.Second), TS: to.Add(-time.Duration(i) * time.Second),
				ClockBasis: flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL, Bytes: 250, Sampling: 1, BytesScaled: 250})
		}
		decoy := rows[0]
		decoy.OutIf, decoy.InIf = 19, 7
		if err := ch.Insert(ctx, append(rows, decoy)); err != nil {
			t.Fatal(err)
		}
	}
	input := whatIfRequest{Target: target, ContextID: f.contextID, TrafficFrom: from.Format(time.RFC3339Nano),
		TrafficTo: to.Format(time.RFC3339Nano), MaximumPollGap: "75s"}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	caFile := verdictEvidenceFile(t, t.TempDir(), "web-ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}))
	readNative := interfaceRoleNativeTLSCaller(t, f, "2026-07-28")
	assert := func(out whatIfResponse, population int) {
		t.Helper()
		traffic := out.Traffic
		if traffic == nil || traffic.ContextID != f.contextID || traffic.Status != "partial" || traffic.FlowRecords != population ||
			traffic.UnattributedRows != population || len(traffic.FailedPorts) < 2 || traffic.FailedPorts[0].InterfaceID == "" ||
			traffic.Projection == nil || traffic.Projection.Complete || traffic.Projection.AffectedBytes != "0" ||
			traffic.Projection.ReroutedBytes != "0" || !traffic.From.Equal(from) || !traffic.To.Equal(to) {
			t.Fatalf("owned source read accepted foreign/unverified rows, or lost its original population %d: %+v", population, traffic)
		}
	}
	readREST := func(tenant string, input whatIfRequest) (whatIfResponse, error) {
		t.Helper()
		args := map[string]any{"target": input.Target, "context_id": input.ContextID, "traffic_from": input.TrafficFrom,
			"traffic_to": input.TrafficTo, "maximum_poll_gap": input.MaximumPollGap, "failure_interface_id": input.FailureInterfaceID}
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		body, err := client.SimulateWhatIf(t.Context(), sdk.SimulateWhatIfRequest{Body: &args})
		if err != nil {
			return whatIfResponse{}, err
		}
		wire, err := json.Marshal(body)
		if err != nil {
			return whatIfResponse{}, err
		}
		var out whatIfResponse
		if err := json.Unmarshal(wire, &out); err != nil {
			return whatIfResponse{}, err
		}
		return out, nil
	}
	for lane, tenant := range f.tenants {
		rest, err := readREST(tenant, input)
		if err != nil {
			t.Fatal(err)
		}
		assert(rest, lane+1)
		var native whatIfResponse
		readNative(tenant, "topology_whatif_traffic", input, &native, true)
		assert(native, lane+1)
		assert(topologyFailureCLIExport(t, socket.URL, f.tokens[tenant], caFile, input), lane+1)
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant],
			Email: "traffic@local.invalid", DisplayName: "Traffic reader", MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		const form = "[aria-label='Traffic simulation inputs']"
		const results = "[aria-label='Traffic simulation results']"
		modeled := fmt.Sprintf("%d flow records lack usable original attribution.", lane+1)
		other := fmt.Sprintf("%d flow records lack usable original attribution.", 2-lane)
		testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/topology?entity_context=" + f.contextID,
			Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}}, TrustCertFiles: []string{caFile}, CAFile: caFile,
			Theme: []string{"light", "dark"}[lane], Accessibility: true, TimeoutMs: 90000, Expect: []string{"Traffic what-if"},
			Steps: []testsupport.RenderStep{
				{Click: "device " + local, Within: "[aria-label='Topology graph']", Expect: []string{"Traffic window start (UTC)"}},
				{Select: form + " select", Value: input.Target},
				{Fill: form + " input[type='datetime-local'] >> nth=0", Value: from.Format("2006-01-02T15:04")},
				{Fill: form + " input[type='datetime-local'] >> nth=1", Value: to.Format("2006-01-02T15:04")},
				{Click: "Simulate traffic impact", Within: form, ExpectWithin: results, Expect: []string{modeled, "Directional link traffic projection"}, Absent: []string{other}},
			}, Controls: []testsupport.RenderControl{{Role: "link", Name: "Export audited traffic simulation"}}})
	}
	for _, tenant := range f.tenants {
		seedTopologyFailureParallelLinks(t, f, tenant, local, remote)
	}
	measuredFrom := f.observedAt(f.tenants[0]).UTC().Truncate(time.Millisecond).Add(time.Millisecond)
	measuredTo := measuredFrom.Add(time.Second)
	if wait := time.Until(measuredTo); wait > 0 {
		if wait > 5*time.Second {
			t.Fatal("fixture source clock is outside the allowed skew")
		}
		time.Sleep(wait)
	}
	window := whatIfRequest{Target: target, ContextID: f.contextID, FailureInterfaceID: f.interfaceID,
		TrafficFrom: measuredFrom.Format(time.RFC3339Nano), TrafficTo: measuredTo.Format(time.RFC3339Nano), MaximumPollGap: "5s"}
	for lane, tenant := range f.tenants {
		seedTopologyFailureMeasuredLoad(t, f, ch, tenant, local, remote, measuredFrom, measuredTo, uint64(lane+1)*1250)
	}
	for lane, tenant := range f.tenants {
		assertMeasured := func(out whatIfResponse) {
			t.Helper()
			traffic := out.Traffic
			bytes := fmt.Sprint((lane + 1) * 1250)
			if traffic == nil || traffic.Status != "projected" || traffic.FlowRecords != 1 || traffic.UnattributedRows != 0 ||
				traffic.Projection == nil || !traffic.Projection.Complete || traffic.Projection.AffectedBytes != bytes || traffic.Projection.ReroutedBytes != bytes {
				t.Fatalf("tenant %d did not project exactly its own authenticated demand: %+v", lane, traffic)
			}
			wantRate := fmt.Sprint((lane + 1) * 10000)
			wantTotal := fmt.Sprint(2000 + (lane+1)*10000)
			var receive, transmit bool
			for _, port := range traffic.Projection.Ports {
				if port.Current.AddedBPS == "0" {
					continue
				}
				if port.Current.AddedBPS != wantRate || port.Current.MeasuredBPS != "2000" || port.Current.ProjectedBPS != wantTotal ||
					port.Current.CapacityBPS != "1000000" || port.ProjectedPeak == nil || port.ProjectedPeak.BPS != wantTotal ||
					port.Direction == "in" && receive || port.Direction == "out" && transmit {
					t.Fatalf("tenant %d lost the survivor's original baseline or peak: %+v", lane, port)
				}
				receive = receive || port.Direction == "in"
				transmit = transmit || port.Direction == "out"
			}
			if !receive || !transmit {
				t.Fatal("wanted both the transmitting and receiving port along the surviving hop")
			}
		}
		rest, err := readREST(tenant, window)
		if err != nil {
			t.Fatal(err)
		}
		assertMeasured(rest)
		var native whatIfResponse
		readNative(tenant, "topology_whatif_traffic", window, &native, true)
		assertMeasured(native)
	}
	a, b := f.tenants[0], f.tenants[1]
	input.FailureInterfaceID = f.interfaceID
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, a, f.roles[a])
		return err
	})
	if _, err := readREST(a, input); err == nil {
		t.Fatal("HTTP simulation kept revoked routing permission")
	}
	readNative(a, "topology_whatif_traffic", input, nil, false)
	var sibling whatIfResponse
	readNative(b, "topology_whatif_traffic", input, &sibling, true)
	assert(sibling, 2)
}

// Use the same app-role storage and operator binding as the receiver. Raw wire
// decoding and the physical comparison are separate lab inputs.
func seedTopologyFailureNeighborViews(t *testing.T, f *roleExplanationAPIFixture, tenant, neighborGeneration string, neighborASN uint32) {
	t.Helper()
	const collector, origin = "role-listener", "role-router"
	profile := store.BGPRoutingBudget{MemoryBytes: 64 << 20, WorkUnits: 64 << 20, StateBytes: 128 << 20, LeaseDuration: 5 * time.Minute}
	routing := store.BGPRouting{}
	const routerID = "192.0.2.1"
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := routing.ReplaceBindingsInScope(ctx, sc, collector, origin, f.contextID, "", []store.BGPRoutingBinding{{ContextID: f.contextID,
			RouterID: f.routerID, Distinguisher: "0000000000000000", BGPIdentifier: routerID, Families: []uint16{1}, SourceFormat: store.BGPRoutingSourceFRRLocRIBV1}},
			profile, func(_ context.Context, target entity.ContextRecord) error {
				if target.TenantID != tenant || target.ContextID != f.contextID {
					return entity.ErrScopeMismatch
				}
				return nil
			})
		return err
	})
	f.peer(tenant, neighborASN)
	stage := func(generation, kind string, peer store.BGPRoutingPeer) {
		t.Helper()
		stamp := f.observedAt(tenant)
		input := store.BGPRoutingPeerUpInput{CollectorAgentID: collector, SenderSerial: f.serials[tenant+collector],
			SourceRef: origin, OriginSerial: f.serials[tenant+origin], ObservationID: generation, ObservedAt: stamp,
			FrameDigest: crypto.Hash([]byte(generation)), Definitions: []store.BGPRoutingViewDefinition{{Kind: kind, AFI: 1, SAFI: 1, Peer: peer}}}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			out, err := routing.StagePeerInScope(ctx, sc, input, profile)
			if err == nil && (out.Status != "staged" || len(out.Views) != 1) {
				t.Fatal("routing lane did not retain one private view", kind, out)
			}
			return err
		})
	}
	loc := store.BGPRoutingPeer{Type: 3, BGPIdentifier: netip.MustParseAddr(routerID), ASN: 64497,
		SourceFormat: store.BGPRoutingSourceFRRLocRIBV1, SentOpen: []byte{1}, ReceivedOpen: []byte{2}}
	locGeneration := pathHealthTestID(t)
	stage(locGeneration, "loc_rib", loc)
	peer := store.BGPRoutingPeer{Type: 0, Address: netip.MustParseAddr("10.42.0.1"), LocalAddress: netip.MustParseAddr("10.42.0.2"),
		BGPIdentifier: netip.MustParseAddr("192.0.2.2"), ASN: neighborASN, SentOpen: []byte{3}, ReceivedOpen: []byte{4}}
	stage(neighborGeneration, "adj_rib_in_post_policy", peer)
	alternate := peer
	alternate.Address, alternate.LocalAddress = netip.MustParseAddr("10.43.0.1"), netip.MustParseAddr("10.43.0.2")
	alternateGeneration := pathHealthTestID(t)
	f.peerAtAddress(tenant, alternate.Address.String(), neighborASN)
	stage(alternateGeneration, "adj_rib_in_post_policy", alternate)
	apply := func(generation string, sender store.BGPRoutingPeer, reset bool, sequence int64, changes []store.BGPRoutingChange) (store.BGPRoutingApplyResult, error) {
		t.Helper()
		var out store.BGPRoutingApplyResult
		stamp := f.observedAt(tenant)
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = routing.ApplyPeerMessageInScope(ctx, sc, store.BGPRoutingStreamInput{PeerSelector: &sender, CollectorAgentID: collector,
				SenderSerial: f.serials[tenant+collector], SourceRef: origin, OriginSerial: f.serials[tenant+origin], Generation: generation,
				ObservedAt: stamp, Sequence: sequence, Reset: reset}, profile, func(_ context.Context, retained store.BGPRoutingPeer, views []store.BGPRoutingStagedView) ([]store.BGPRoutingBatch, error) {
				if reset || len(views) != 1 || retained.Type != sender.Type || retained.Address != sender.Address {
					t.Fatal("authenticated route frame entered another view or was decoded after refusal")
				}
				return []store.BGPRoutingBatch{{AFI: 1, SAFI: 1, EndOfRIB: len(changes) == 0, Changes: changes,
					WireDigest: crypto.Hash([]byte(fmt.Sprint("modeled whole unicast frame ", sequence)))}}, nil
			})
			return err
		})
		return out, err
	}
	forged := peer
	forged.Address = netip.MustParseAddr("10.42.0.3")
	if _, err := apply(neighborGeneration, forged, true, 1, nil); !errors.Is(err, store.ErrBGPRoutingView) {
		t.Fatal("a different address could retire this authenticated neighbor view", err)
	}
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	for _, check := range []struct {
		generation string
		peer       store.BGPRoutingPeer
		nextHop    netip.Addr
	}{{locGeneration, loc, peer.Address}, {neighborGeneration, peer, peer.Address}, {alternateGeneration, alternate, alternate.Address}} {
		changes := []store.BGPRoutingChange{{Prefix: prefix, Segments: []store.BGPRoutingSegment{{Kind: 2, Values: []uint32{neighborASN}}},
			Attributes: store.BGPRoutingAttributes{Wire: []store.BGPRoutingAttribute{{Flags: 64, Type: 1, Value: []byte{0}}}}, NextHops: []netip.Addr{check.nextHop}}}
		if out, err := apply(check.generation, check.peer, false, 1, changes); err != nil || out.Status != "applied" {
			t.Fatal("physical neighbor and selected route updates did not stage independently", check.peer.Type, out, err)
		}
		if out, err := apply(check.generation, check.peer, false, 2, nil); err != nil || out.Status != "applied" {
			t.Fatal("physical neighbor and selected route generations did not publish independently", check.peer.Type, out, err)
		}
	}
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var current int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE state='current' AND generation=$1`, neighborGeneration).Scan(&current); err != nil {
			return err
		}
		if current != 1 {
			t.Fatalf("tenant storage read %d neighbor views using the shared generation", current)
		}
		return nil
	})
	scope := entity.Scope{TenantID: tenant, ContextID: f.contextID}
	if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		out, err := routing.LookupRouterFailureInScope(ctx, sc, scope, f.routerID, netip.MustParseAddr("203.0.113.1"), profile)
		if err != nil {
			return err
		}
		if !out.Complete || len(out.Neighbors) != 2 || out.Selected.View.Generation != locGeneration ||
			!slices.ContainsFunc(out.Neighbors, func(exit store.BGPRoutingFailureNeighbor) bool {
				return exit.Peer == peer.Address && exit.Local == peer.LocalAddress && exit.ASN == neighborASN &&
					exit.Route.View.Generation == neighborGeneration && exit.Route.Prefix == prefix
			}) || !slices.ContainsFunc(out.Neighbors, func(exit store.BGPRoutingFailureNeighbor) bool {
			return exit.Peer == alternate.Address && exit.Local == alternate.LocalAddress && exit.ASN == neighborASN &&
				exit.Route.View.Generation == alternateGeneration && exit.Route.Prefix == prefix
		}) {
			t.Fatal("paired failure lookup separated neither selected nor post-policy views by owned source", out)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func topologyFailureCLIExport(t *testing.T, endpoint, token, ca string, input whatIfRequest) whatIfResponse {
	t.Helper()
	env := map[string]string{"PROBECTL_API_URL": endpoint, "PROBECTL_API_TOKEN": token, "PROBECTL_CA_FILE": ca}
	args := []string{"topology", "whatif-export", "--query", "target=" + input.Target, "--query", "context_id=" + input.ContextID,
		"--query", "traffic_from=" + input.TrafficFrom, "--query", "traffic_to=" + input.TrafficTo,
		"--query", "maximum_poll_gap=" + input.MaximumPollGap, "--json"}
	var output, stderr bytes.Buffer
	if code := cli.RunWithStdin(args, func(key string) string { return env[key] }, nil, &output, &stderr); code != 0 {
		t.Fatalf("audited traffic CLI export failed: %d %s", code, stderr.String())
	}
	var out whatIfResponse
	if err := json.Unmarshal(output.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func seedTopologyFailureParallelLinks(t *testing.T, f *roleExplanationAPIFixture, tenant, local, remote string) {
	t.Helper()
	const snmp, exporter = "role-snmp", "role-flow"
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
VALUES($1,$2,'flow_exporter',$3,$4,$5)`, tenant, exporter, remote, f.contextID, f.otherRouter)
		return err
	})
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	registry := store.NewEntityRegistry(f.pool)
	stamp := f.observedAt(tenant)
	var polls, adjacency []entity.Observation
	for _, link := range []struct {
		target, other, portAddress, remotePort string
		index                                  uint32
	}{
		{local, remote, "10.42.0.2", "eth9", 7},
		{local, remote, "10.43.0.2", "eth10", 8},
		{remote, local, "10.42.0.1", "eth7", 9},
		{remote, local, "10.43.0.1", "eth8", 10},
	} {
		source := entity.SourceKey{AgentID: snmp, Kind: entity.DeviceTarget, SourceRef: link.target}
		index := fmt.Sprint(link.index)
		port, ref := "eth"+index, "snmp:ifIndex:"+index
		neighbor := "neighbor:fx11-" + port + "-to-" + link.remotePort
		chassis := "00:11:22:33:44:55"
		if link.target == remote {
			chassis = "00:11:22:33:44:66"
		}
		polls = append(polls,
			entity.Observation{ID: pathHealthTestID(t), Source: source, Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: index}, SourceRef: ref, ObservedAt: stamp},
			entity.Observation{ID: pathHealthTestID(t), Source: source, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: link.portAddress}, SourceRef: ref, ObservedAt: stamp},
		)
		adjacency = append(adjacency, entity.Observation{ID: pathHealthTestID(t), Source: source,
			Alias: entity.AliasKey{Kind: entity.PhysicalNeighborAlias, Value: neighbor}, SourceRef: neighbor,
			NeighborProtocol: "lldp", NeighborLocalIfIndex: link.index, NeighborLocalPortID: port, NeighborRemotePortID: link.remotePort,
			NeighborChassisID: chassis, NeighborDeviceName: "fx11-" + link.other, NeighborAddress: link.other})
	}
	serial := f.serials[tenant+snmp]
	if count, unresolved, err := writeEntityEvidenceBatchForTest(ctx, registry, snmp, serial, polls); err != nil || count != len(polls) || unresolved != 0 {
		t.Fatal("physical interface observations were refused", count, unresolved, err)
	}
	stamp = f.observedAt(tenant)
	for i := range adjacency {
		adjacency[i].ObservedAt = stamp
	}
	if count, unresolved, err := writeEntityEvidenceBatchForTest(ctx, registry, snmp, serial, adjacency); err != nil || count != len(adjacency) || unresolved != 0 {
		t.Fatal("parallel reciprocal physical links were refused", count, unresolved, err)
	}
	claim := entity.Observation{ID: pathHealthTestID(t), Source: entity.SourceKey{AgentID: exporter, Kind: entity.FlowExporter, SourceRef: remote},
		Alias: entity.AliasKey{Kind: entity.FlowExporterAlias, Value: remote + "/ipfix/4294967295"}, SourceRef: "flow:ipfix:domain:4294967295", ObservedAt: f.observedAt(tenant)}
	if count, unresolved, err := writeEntityEvidenceBatchForTest(ctx, registry, exporter, f.serials[tenant+exporter], []entity.Observation{claim}); err != nil || count != 1 || unresolved != 0 {
		t.Fatal("remote exporter was refused", count, unresolved, err)
	}
}

type topologyFailureMeasurementWriter interface {
	Insert(context.Context, []flowstore.Row) error
	InsertCounterPoll(context.Context, []flowstore.CounterRow, flowstore.CounterBudget) error
}

func seedTopologyFailureMeasuredLoad(t *testing.T, f *roleExplanationAPIFixture, ch topologyFailureMeasurementWriter, tenant, local, remote string,
	from, to time.Time, failedBytes uint64) {
	t.Helper()
	const snmp, exporter = "role-snmp", "role-flow"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	profile := store.BGPRoutingBudget{MemoryBytes: 64 << 20, WorkUnits: 64 << 20, StateBytes: 128 << 20}
	record := &flowv1.FlowRecord{TenantId: tenant, AgentId: exporter, ExporterAddress: local,
		SourceAddress: "198.51.100.1", DestinationAddress: "203.0.113.1", FlowProtocol: "ipfix", ObservationDomain: 4294967295,
		OutputInterface: 7, NextHop: "10.42.0.1", StartUnixNano: from.UnixNano(), EndUnixNano: to.UnixNano(), ObservedAtUnixNano: to.UnixNano(),
		ClockBasis: flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL, Bytes: failedBytes, SamplingRate: 1, BytesScaled: failedBytes}
	raw, input, err := flow.RoutingCaptureWitness(ctx, record, profile.MemoryBytes, profile.WorkUnits)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.NewBGPRoutingFlowCaptures(f.pool).CaptureAuthenticated(ctx, exporter, raw, input, profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Insert(ctx, []flowstore.Row{{TenantID: tenant, AgentID: exporter, Exporter: local, Protocol: input.Protocol, ObsDomain: input.Domain,
		OutIf: record.OutputInterface, SrcAddr: input.Source.String(), DstAddr: input.Destination.String(), NextHop: record.NextHop, TS: to, StartTS: from,
		ClockBasis: record.ClockBasis, Bytes: record.Bytes, Sampling: record.SamplingRate, BytesScaled: record.BytesScaled,
		RawFlowDigest: hex.EncodeToString(raw[:]), RoutingCaptureKey: hex.EncodeToString(ref.Key[:]), RoutingCapturedUnixNanos: ref.CapturedAt.UnixNano()}}); err != nil {
		t.Fatal(err)
	}
	reader := store.NewDeviceCounterCaptures(f.pool)
	budget := flowstore.CounterBudget{MemoryBytes: 32 << 20, WorkUnits: 32 << 20, Timeout: 10 * time.Second}
	for _, device := range []struct {
		address, id string
		primary     uint32
	}{{local, f.routerID, 7}, {remote, f.otherRouter, 9}} {
		for poll, at := range []time.Time{from, to} {
			input := entity.CounterCaptureInput{ConfiguredTarget: device.address, PollStartedAt: at, PollCompletedAt: at, PointCount: 4}
			digest := [32]byte{byte(device.primary), byte(poll + 1)}
			ref, err := reader.CaptureAuthenticated(ctx, snmp, f.serials[tenant+snmp], digest, input, 32<<20)
			if err != nil {
				t.Fatal(err)
			}
			witness, err := reader.LookupWitness(ctx, snmp, digest, input)
			if err != nil {
				t.Fatal(err)
			}
			var rows []flowstore.CounterRow
			for _, index := range []uint32{device.primary, device.primary + 1} {
				for _, direction := range []string{"in", "out"} {
					increment := uint64(250)
					if index == device.primary {
						increment = 0
						if device.address == local && direction == "out" || device.address == remote && direction == "in" {
							increment = failedBytes
						}
					}
					rows = append(rows, flowstore.CounterRow{TenantID: tenant,
						CounterSource: flowstore.CounterSource{ContextID: f.contextID, DeviceID: device.id, AgentID: snmp, SourceRef: device.address,
							SourceAssignedAt: witness.SourceAssignedAt, AgentAssignedAt: witness.AgentAssignedAt},
						SenderSerial: witness.SenderSerial, CaptureKey: ref.Key, RawDigest: digest, CapturedAt: ref.CapturedAt, PollStartedAt: at, PollCompletedAt: at,
						Population: input.PointCount, IfIndex: index, Name: "probectl.device.if." + direction + ".octets", Value: 10000 + uint64(poll)*increment, Width: 64,
						UptimeTicks: 10000 + uint32(poll)*100, UptimeKnown: true, DiscontinuityKnown: true, InterfaceSpeedBPS: 1_000_000, InterfaceSpeedKnown: true})
				}
			}
			if err := ch.InsertCounterPoll(ctx, rows, budget); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func seedTopologyFailureLink(t *testing.T, f *roleExplanationAPIFixture, graph *topology.MemoryStore, tenant, local, remote string) {
	t.Helper()
	const agent = "role-snmp"
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "topology.read"); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
VALUES($1,$2,'device_target',$3,$4,$5)`, tenant, agent, remote, f.contextID, f.otherRouter)
		return err
	})
	at := f.observedAt(tenant)
	neighbor := "neighbor:fx11-eth7-to-eth9"
	claims := []entity.Observation{
		{ID: pathHealthTestID(t), Source: entity.SourceKey{AgentID: agent, Kind: entity.DeviceTarget, SourceRef: remote},
			Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: remote}, SourceRef: "snmp:configured-target", ObservedAt: at},
		{ID: pathHealthTestID(t), Source: entity.SourceKey{AgentID: agent, Kind: entity.DeviceTarget, SourceRef: local},
			Alias: entity.AliasKey{Kind: entity.PhysicalNeighborAlias, Value: neighbor}, SourceRef: neighbor, ObservedAt: at,
			NeighborProtocol: "lldp", NeighborLocalIfIndex: 7, NeighborLocalPortID: "eth7", NeighborRemotePortID: "eth9",
			NeighborChassisID: "00:11:22:33:44:55", NeighborDeviceName: "fx11-other", NeighborAddress: remote},
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	if accepted, unresolved, err := writeEntityEvidenceBatchForTest(ctx, store.NewEntityRegistry(f.pool), agent, f.serials[tenant+agent], claims); err != nil || accepted != len(claims) || unresolved != 0 {
		t.Fatal("fixture did not resolve owned physical evidence", accepted, unresolved, err)
	}
	owner, err := graph.ForTenant(tenant)
	if err != nil {
		t.Fatal(err)
	}
	owner.ObservePhysicalAdjacency(topology.PhysicalAdjacencyInput{LocalAddress: local, RemoteAddress: remote,
		LocalPort: "eth7", RemotePort: "eth9", Protocol: "lldp", SourceAgent: agent, FreshUntil: at.Add(time.Hour)}, at)
}
