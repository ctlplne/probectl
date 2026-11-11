// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// Real FRR/SNMP, issued mTLS collectors, current app-role PG/RLS, Kafka,
// ClickHouse and HTTPS/CLI. IPFIX records and complete IX files are generated
// fixtures: the exporter timestamps supply the hand-calculated interval grid;
// routing is independently captured when each record is ingested. This does
// not claim historical forwarding, a live IX session or lossless telemetry.
func TestFRRPeeringEstimateJoinsCurrentSourcesAndCombinedHandP95(t *testing.T) {
	if runtime.GOOS != "linux" {
		testsupport.SkipOrFatal(t, "peering source integration needs a Linux route to the owned FRR bridge")
	}
	lab := startRoutingLabNamed(t, "probectl-qa-beta-peering-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	links := []roleRouterLink{
		addRoleRouterLink(t, lab, "transit", "edge", 234, edgeASN, entity.InterfaceRoleTransit),
		addRoleRouterLink(t, lab, "ix", "rrc", 232, rrcASN, entity.InterfaceRoleIX),
		addRoleRouterLink(t, lab, "second-transit", "rtr-b", 233, rtrBASN, entity.InterfaceRoleTransit),
	}
	lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(rtrAASN), "-c", "neighbor "+lab.ip["edge"]+" shutdown", "-c", "bmp targets probectl", "-c", "bmp monitor ipv4 unicast loc-rib", "-c", "bmp monitor ipv6 unicast loc-rib", "-c", "bmp stats interval 1000", "-c", "end")
	// The new direct transit has no inherited single-prefix export filter.
	// Retain and verify the complete three-prefix source, including the routes
	// outside this particular peering traffic selection.
	lab.awaitRoutes(t, "rtr-a", map[string]string{prefixA: path(edgeASN, originA), prefixB: path(edgeASN, originB), prefixDecoy: path(edgeASN, originDecoy)})
	community := startRouterSNMP(t, lab, "rtr-a")
	for i := range links {
		index := queryEdgeSNMP(t, lab.name+"-rtr-a-snmp", community, ".1.3.6.1.2.1.4.20.1.2."+links[i].routerIP)
		value, err := strconv.ParseUint(index, 10, 32)
		if err != nil || value == 0 {
			t.Fatal("peering handoff lost its real kernel SNMP index", index, err)
		}
		links[i].index = uint32(value)
		for j := 0; j < i; j++ {
			if links[j].index == links[i].index {
				t.Fatal("independent peering handoffs shared a kernel interface")
			}
		}
	}
	files := peeringRouterPublicFixtures(t, links[1])
	st := shipped.Start(t, shipped.Options{Name: "peeringhand", TenantBand: 4, Env: files})
	first := registerEdgeFlowEvidence(t, st, lab.ip["rtr-a"])
	second := registerSecondRouterTenant(t, st, first)
	registrations := []edgeFlowRegistration{first, second}
	ids := make([]map[uint32]string, 2)
	listeners := make([]*bgpTenant, 2)
	bindings := make([]store.BGPRoutingBindingConfiguration, 2)
	destinations := make([]string, 2)
	cliEnvironments := make([]map[string]string, 2)
	for lane, reg := range registrations {
		requireRoleSourceBinding(t, st, reg, map[string]string{"agent_id": reg.agentID, "source_kind": "flow_exporter", "source_ref": lab.ip["rtr-a"], "context_id": reg.contextID, "anchor_entity_id": reg.deviceID})
		agent := startShippedEdgeSNMP(t, st, reg, "peering-"+strconv.Itoa(lane), lab.ip["rtr-a"], community)
		awaitEdgeSNMPEvidence(t, st, reg, agent, lab.ip["rtr-a"])
		ids[lane] = awaitRoleRouterInterfaces(t, st, reg, links)
		listeners[lane] = startRouterBMPEvidenceListenerNamed(t, st, lab, reg, reg.deviceID, "peering-"+strconv.Itoa(lane))
		bindings[lane] = putFRRSelectedRIBBinding(t, st, reg, listeners[lane], lab.ip["rtr-a"], "", true)
		listeners[lane].reconnectBMP()
		awaitFRRSelectedPath(t, st.ApplicationReadPool(t), reg, "203.0.113.1", prefixA, []uint32{edgeASN, originA}, netip.MustParseAddr(links[0].peerIP))
		putRoleRouterPolicy(t, st, reg, entity.InterfaceRolePolicyRecord{}, []uint32{edgeASN, rtrBASN}, nil)
		awaitRoleRouterLabels(t, st, reg, links, ids[lane])
		destinations[lane] = startShippedRouterFlow(t, st, lab, reg, lab.ip["rtr-a"])
		cliEnvironments[lane] = map[string]string{"PROBECTL_API_TOKEN": st.APIToken(t, reg.cookie, "read", "ai.query")}
	}
	// No timer advances a routing lease. Real FRR statistics keep the current
	// sources alive while the delayed-export timestamps exercise twenty complete
	// five-minute intervals. Opposite peaks make sum(per-link p95) incorrect.
	from := time.Now().UTC().Truncate(time.Second).Add(-100 * time.Minute)
	for lane, destination := range destinations {
		for interval := range 20 {
			packet := peeringRouterIPFIX(t, from.Add(time.Duration(interval)*5*time.Minute), interval, uint64(1+2*lane), []uint32{links[0].index, links[2].index})
			sendOwnedRouterGolden(t, lab, destination, packet)
		}
	}
	input := flow.PeeringEstimateInput{PeerASN: originA, IXID: "71", LANID: "11", Direction: "inbound", From: from, To: from.Add(100 * time.Minute), BucketSeconds: 300, DataSeries: "raw"}
	read := func(lane int, selected flow.PeeringEstimateInput) (int, flow.PeeringEstimateResponse) {
		t.Helper()
		reg := registrations[lane]
		selected.ContextID, selected.InterfaceID = reg.contextID, ids[lane][links[1].index]
		code, raw := st.Do(t, reg.cookie, http.MethodPost, "/v1/flows/peering-estimate", selected)
		var out flow.PeeringEstimateResponse
		if code == http.StatusOK && json.Unmarshal(raw, &out) != nil {
			t.Fatal("served peering estimate lost its whole public response")
		}
		return code, out
	}
	for lane, reg := range registrations {
		for _, direction := range []string{"inbound", "outbound"} {
			selected := input
			selected.Direction = direction
			var last flow.PeeringEstimateResponse
			shipped.Await(t, "original joined peering hand p95 on both tenant-owned transits", time.Minute, func() bool {
				code, out := read(lane, selected)
				last = out
				return code == http.StatusOK && peeringRouterHandMatches(out, reg, ids[lane], links, lane)
			})
			selected.ContextID, selected.InterfaceID = reg.contextID, ids[lane][links[1].index]
			var command flow.PeeringEstimateResponse
			st.MustCLI(t, cliEnvironments[lane], &command, "peering", "estimate", "--body-file", st.SecretFile(t, selected))
			if !peeringRouterHandMatches(command, reg, ids[lane], links, lane) || command.P95 == nil || last.P95 == nil || *command.P95 != *last.P95 {
				t.Fatal("CLI lost the original source-joined combined hand p95")
			}
		}
		missing := input
		missing.From = missing.From.Add(-5 * time.Minute)
		code, gap := read(lane, missing)
		if code != http.StatusOK || !gap.Target.Eligible || gap.P95 != nil || gap.Coverage.CompleteObservedInputs || gap.Coverage.ExpectedIntervals != 21 || gap.Coverage.ObservedIntervals != 20 || gap.Reason != "missing_observed_intervals" {
			t.Fatal("served source-joined peering manufactured an observed zero for a missing interval", code, gap)
		}
		foreign := input
		foreign.ContextID, foreign.InterfaceID = registrations[1-lane].contextID, ids[1-lane][links[1].index]
		code, _ = st.Do(t, reg.cookie, http.MethodPost, "/v1/flows/peering-estimate", foreign)
		if code == http.StatusOK {
			t.Fatal("source-joined peering accepted the sibling tenant's canonical target")
		}
	}
	provePeeringRouterStdio(t, st, registrations, ids, links, input)
	renderPeeringRouterEstimates(t, st, registrations, ids, links, input)
	// An operator withdraws A's exact live routing delegation; neither the
	// existing socket nor captured history can authorize the former result.
	putFRRSelectedRIBBinding(t, st, first, listeners[0], lab.ip["rtr-a"], bindings[0].Manifest.Epoch, false)
	if code, out := read(0, input); code == http.StatusOK && out.P95 != nil && out.P95.BitsPerSecondNumerator == "101000000000" {
		t.Fatal("source-joined peering retained withdrawn current routing authority")
	}
	if code, out := read(1, input); code != http.StatusOK || !peeringRouterHandMatches(out, second, ids[1], links, 1) {
		t.Fatal("routing delegation withdrawal damaged the sibling tenant's complete estimate", code)
	}
	t.Log("real-integration: FRR selected RIB + same-kernel SNMP + issued IPFIX/evidence mTLS + app-role PG/RLS + Kafka/ClickHouse + HTTPS/CLI and shipped modern/legacy stdio; generated delayed-export twenty-interval two-transit hand101/303Gbps, both directions, missing-input/foreign-target/current-token/current-delegation controls; synthetic IX, no historical forwarding or live peering claim")
}

func peeringRouterHandMatches(out flow.PeeringEstimateResponse, reg edgeFlowRegistration, ids map[uint32]string, links []roleRouterLink, lane int) bool {
	multiplier := int64(1 + 2*lane)
	if !out.Preview || !out.Target.Eligible || out.Target.ContextID != reg.contextID || out.Target.RouterID != reg.deviceID || out.Target.InterfaceID != ids[links[1].index] || len(out.Target.PrefixIDs) != 2 || len(out.Target.MemberIDs) != 1 || !out.Coverage.CompleteObservedInputs || !out.Coverage.CompleteClassification || out.Coverage.ExpectedIntervals != 20 || out.Coverage.ObservedIntervals != 20 || out.Bytes["eligible_transit"] != strconv.FormatInt(multiplier*8_925_000_000_000, 10) || out.P95 == nil || out.P95.BitsPerSecondNumerator != strconv.FormatInt(multiplier*101_000_000_000, 10) || out.P95.BitsPerSecondDenominator != "1" || out.P95.Rank != 19 || out.P95.Intervals != 20 || out.P95.Nonzero != 20 || len(out.Transit) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, transit := range out.Transit {
		if (transit.InterfaceID != ids[links[0].index] && transit.InterfaceID != ids[links[2].index]) || seen[transit.InterfaceID] || transit.P95.BitsPerSecondNumerator != strconv.FormatInt(multiplier*1_000_000_000, 10) || transit.P95.BitsPerSecondDenominator != "1" || transit.P95.Rank != 19 || transit.P95.Intervals != 20 {
			return false
		}
		seen[transit.InterfaceID] = true
	}
	return true
}

func peeringRouterPublicFixtures(t *testing.T, ix roleRouterLink) map[string]string {
	t.Helper()
	write := func(name string, body any) string {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		name = filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(name, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return name
	}
	at := time.Now().UTC().Add(-time.Second)
	return map[string]string{
		"PROBECTL_FLOW_ENRICH_IX_PREFIX_FILE":     write("ixpfx.json", map[string]any{"version": 1, "object": "ixpfx", "observed_at": at, "complete": true, "record_count": 2, "data": []map[string]any{{"id": 7, "ixlan_id": 11, "protocol": "IPv4", "prefix": ix.prefix, "status": "ok"}, {"id": 8, "ixlan_id": 11, "protocol": "IPv6", "prefix": ix.prefix6, "status": "ok"}}}),
		"PROBECTL_FLOW_ENRICH_IX_MEMBERSHIP_FILE": write("netixlan.json", map[string]any{"version": 1, "object": "netixlan", "observed_at": at, "complete": true, "record_count": 1, "data": []map[string]any{{"id": 1, "ix_id": 71, "ixlan_id": 11, "asn": originA, "status": "ok", "operational": true}}}),
	}
}

func sendOwnedRouterGolden(t *testing.T, lab *routingLab, destination string, packet []byte) {
	t.Helper()
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "docker", "exec", "-i", lab.container("rtr-a"), "bash", "-c", `cat > /dev/udp/"$1"/"$2"`, "owned-flow-golden", host, port)
	command.Stdin = bytes.NewReader(packet)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("owned router peering golden failed: %v %.400s", err, out)
	}
}

func peeringRouterIPFIX(t *testing.T, start time.Time, interval int, multiplier uint64, interfaces []uint32) []byte {
	t.Helper()
	if len(interfaces) != 2 || interval < 0 || interval >= 20 || (multiplier != 1 && multiplier != 3) || start.UnixMilli() <= 0 {
		t.Fatal("invalid independent peering hand fixture")
	}
	fields := []uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 8, 2, 8, 10, 4, 14, 4, 152, 8, 153, 8}
	template := routingGoldenWire(t, uint16(258), routingGoldenHalf(t, len(fields)/2), fields)
	template = append(routingGoldenWire(t, uint16(2), routingGoldenHalf(t, 4+len(template))), template...)
	var records []byte
	for link, index := range interfaces {
		volume := multiplier * 37_500_000_000
		if interval == 18+link {
			volume *= 100
		}
		records = append(records, routingGoldenWire(t, [4]byte{203, 0, 113, 1}, [4]byte{203, 0, 113, 2}, routingGoldenHalf(t, 42000+2*interval+link), uint16(443), uint8(6), volume, uint64(10), index, index, uint64(start.UnixMilli()), uint64(start.Add(time.Second).UnixMilli()))...)
	}
	body := append(template, routingGoldenWire(t, uint16(258), routingGoldenHalf(t, 4+len(records)))...)
	body = append(body, records...)
	return append(routingGoldenWire(t, uint16(10), routingGoldenHalf(t, 16+len(body)), routingGoldenWord(t, time.Now().Unix()), routingGoldenWord(t, int64(2*interval)), uint32(4294967295)), body...)
}
