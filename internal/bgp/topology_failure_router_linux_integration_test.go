// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package bgp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
	"github.com/ctlplne/probectl/internal/topology"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type failureLabPort struct {
	Name  string `json:"ifname"`
	Index uint32 `json:"ifindex"`
	MAC   string `json:"address"`
}

type failureLabRouter struct {
	name, address, community string
	neighborRows             string
	ports                    []failureLabPort
}

func prepareFailureLabSNMP(t *testing.T, lab *routingLab, links []roleRouterLink) []failureLabRouter {
	t.Helper()
	const local = "rtr-a"
	routers := []failureLabRouter{{name: local, address: lab.ip[local]}}
	var localNeighbors strings.Builder
	for _, link := range links {
		out := readFailureLabPort(t, lab, local, link.routerIP, link.peerIP)
		in := readFailureLabPort(t, lab, link.peer, link.peerIP, link.routerIP)
		peer := failureLabRouter{name: link.peer, address: lab.ip[link.peer], ports: []failureLabPort{in}}
		localNeighbors.WriteString(failureLabNeighborRows(out, in, peer.address))
		peer.neighborRows = failureLabNeighborRows(in, out, routers[0].address)
		peer.community = startRouterSNMPWithNeighbors(t, lab, peer.name, "fx11-"+peer.name, "")
		routers = append(routers, peer)
		routers[0].ports = append(routers[0].ports, out)
	}
	routers[0].neighborRows = localNeighbors.String()
	routers[0].community = startRouterSNMPWithNeighbors(t, lab, local, "fx11-"+local, "")
	return routers
}

func quietFailureLabHandoffs(t *testing.T, lab *routingLab, links [2]roleRouterLink, routers []failureLabRouter) {
	t.Helper()
	// Wait for the original IPv4 routes and signed adjacency before changing
	// the peer interfaces. ARP and IPv6 discovery would otherwise count as
	// offered reverse load in the closed IPv4 measurement window.
	local := lab.container(routers[0].name)
	for i, link := range links {
		peer := lab.container(link.peer)
		out, in := routers[0].ports[i], routers[i+1].ports[0]
		lab.docker(t, "exec", peer, "ip", "link", "set", "dev", in.Name, "addrgenmode", "none")
		lab.docker(t, "exec", peer, "ip", "-6", "address", "flush", "dev", in.Name)
		lab.docker(t, "exec", local, "ip", "neighbor", "replace", link.peerIP,
			"lladdr", in.MAC, "nud", "permanent", "dev", out.Name)
		lab.docker(t, "exec", peer, "ip", "neighbor", "replace", link.routerIP,
			"lladdr", out.MAC, "nud", "permanent", "dev", in.Name)
	}
}

func registerFailureLabPeer(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, peer failureLabRouter) edgeFlowRegistration {
	t.Helper()
	code, body := st.Do(t, reg.cookie, http.MethodPost, "/v1/entities", map[string]string{
		"context_id": reg.contextID, "kind": "device", "label": "fx11-" + peer.name,
	})
	var result struct{ ID string }
	if code != http.StatusCreated || json.Unmarshal(body, &result) != nil || result.ID == "" {
		t.Fatalf("create the owned %s topology device: HTTP %d %.400s", peer.name, code, body)
	}
	reg.deviceID = result.ID
	return reg
}

// The SNMP daemon exposes adjacency rows derived from the lab's kernel ports.
// FRRouting, the signed collectors, and the independent post-failure kernel
// counters run normally. Only the fixture operator interrupts the link.
func TestFRRTopologyWhatIfMatchesIndependentFailoverCounters(t *testing.T) {
	lab := startRoutingLabNamed(t, "probectl-qa-beta-fx11-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	links := configureTransferStockRoutes(t, lab)
	routers := prepareFailureLabSNMP(t, lab, links[:])
	readTransferStockInterfaces(t, lab, &links, routers[0].community)
	lab.docker(t, "exec", "--user", "0", lab.container("rrc"), "ip", "route", "replace", transferStockAddress+"/32", "via", routers[0].address)
	lab.docker(t, "exec", lab.container("rtr-b"), "ip", "route", "replace", transferStockAddress+"/32", "via", routers[1].address)
	st := shipped.Start(t, shipped.Options{Name: "fx11-failover", TenantBand: 4})
	first := registerEdgeFlowEvidence(t, st, routers[0].address)
	second := registerEdgeFlowEvidence(t, st, routers[0].address, registerSecondRouterTenant(t, st, first))
	lanes := [2]transferStockLane{{reg: first}, {reg: second}}
	defer func() {
		if t.Failed() {
			logFailureLabRouting(t, lab, st, links, lanes)
		}
	}()
	prepareTransferStockCollectors(t, lab, st, links, routers[0].community, buildRoleRouterExporter(t, lab), &lanes)
	var devices [2][]string
	for lane, original := range lanes {
		devices[lane] = append(devices[lane], original.reg.deviceID)
		for _, router := range routers[1:] {
			owned := registerFailureLabPeer(t, st, original.reg, router)
			name := fmt.Sprintf("fx11-%d-%s", lane, router.name)
			agent := startShippedEdgeSNMP(t, st, owned, name, router.address, router.community)
			awaitEdgeSNMPEvidence(t, st, owned, agent, router.address)
			devices[lane] = append(devices[lane], owned.deviceID)
		}
	}
	// Advertise the observed neighbors once both ends have current ownership
	// evidence. Unresolved first polls otherwise wait for the agent's normal
	// retry interval. A newly observed neighbor refreshes that fingerprint.
	for _, router := range routers {
		writeRouterSNMPConfig(t, lab, router.name, "fx11-"+router.name, router.community, router.neighborRows)
		lab.docker(t, "restart", "-t", "2", lab.name+"-"+router.name+"-snmp")
	}
	for lane, registered := range lanes {
		awaitFailureLabLinks(t, st, registered.reg, routers, devices[lane], devices[1-lane])
	}
	quietFailureLabHandoffs(t, lab, links, routers)
	warmTransferStockExporters(t, lab, st, links[0], lanes)
	for _, lane := range lanes {
		lab.docker(t, "stop", "-t", "2", lane.exporter)
	}
	packets := [2]int{transferStockPackets / 2, transferStockPackets}
	var predictions [2]sdk.TopologyFailurePortLoad
	for i := range lanes {
		predictions[i] = predictFailureLabTraffic(t, lab, st, links, routers, &lanes[i], packets[i])
	}
	for i, lane := range lanes {
		assertFailureLabScope(t, st, lane, lanes[1-i], routers[0].address, routers[1].address)
	}
	assertTransferStockKernelPath(t, lab, links[0])
	router := lab.container("rtr-a")
	t.Cleanup(func() { lab.docker(t, "exec", router, "ip", "link", "set", "dev", links[0].iface, "up") })
	lab.docker(t, "exec", router, "ip", "link", "set", "dev", links[0].iface, "down")
	waitFailureLabPath(t, lab, links[1])
	for lane, prediction := range predictions {
		span := lanes[lane].after.started.Sub(lanes[lane].before.started)
		measured, capacity := measureFailureLabSurvivor(t, lab, links[1], packets[lane], span)
		assertFailureLabUtilization(t, prediction, measured, capacity)
	}
}

func logFailureLabRouting(t *testing.T, lab *routingLab, st *shipped.Stack, links [2]roleRouterLink, lanes [2]transferStockLane) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	summary, err := exec.CommandContext(ctx, "docker", "exec", lab.container("rtr-a"),
		"vtysh", "-c", "show bgp ipv4 unicast summary json").Output()
	if err != nil {
		t.Logf("fixture IPv4 session summary unavailable: %v", err)
	} else {
		for _, link := range links {
			t.Logf("fixture %s peer %s established=%v",
				link.name, link.peerIP, roleRouterSessionEstablished(summary, link.peerIP))
		}
	}
	pool := st.ApplicationReadPool(t)
	for _, lane := range lanes {
		logFRRRoutingState(t, pool, lane.reg)
		logRoleRouterPeerAuthority(t, pool, lane.reg)
	}
}

func predictFailureLabTraffic(t *testing.T, lab *routingLab, st *shipped.Stack, links [2]roleRouterLink,
	routers []failureLabRouter, lane *transferStockLane, packetCount int) sdk.TopologyFailurePortLoad {
	t.Helper()
	installRoutingLabWorkload(t, lab, packetCount, transferStockPayload, "edge", "rrc")
	lab.docker(t, "start", lane.exporter)
	shipped.Await(t, "owned exporter control socket", 15*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "docker", "exec", lane.exporter, "softflowctl", "-c", "/tmp/softflowd.ctl", "delete-all").Run() == nil
	})
	lane.before = awaitFailureLabPoll(t, *lane, links, time.Now())
	sendRoutingLabPayload(t, lab, "rrc", lab.ip["rrc"], func(counts []byte) { t.Logf("baseline receiver: %s", counts) })
	if t.Failed() {
		t.FailNow()
	}
	lane.after = awaitFailureLabPoll(t, *lane, links, time.Now())
	verifyTransferStockPolls(t, st, lane)
	bytes := packetCount * (transferStockPayload + 28)
	if !routingLabCaptureComplete(t.Context(), lane.exporter, packetCount, bytes) {
		drainTransferStockCapture(t, lab, links[0])
	}
	shipped.Await(t, "stock IPFIX captured the exact baseline payload", 12*time.Second, func() bool {
		return routingLabCaptureComplete(t.Context(), lane.exporter, packetCount, bytes)
	})
	lab.docker(t, "exec", lane.exporter, "softflowctl", "-c", "/tmp/softflowd.ctl", "expire-all")
	input := failureLabWhatIf(*lane, *lane, routers[0].address, routers[1].address)
	var traffic sdk.TopologyFailureTraffic
	var status int
	defer func() {
		if t.Failed() {
			t.Logf("last topology prediction: HTTP %d, status=%s reason=%s records=%d unattributed=%d",
				status, traffic.Status, traffic.Reason, traffic.FlowRecords, traffic.UnattributedRows)
			t.Logf("source counter bracket: %s %v to %s %v, local interfaces: %v",
				lane.before.started.Format(time.RFC3339Nano), lane.before.octets,
				lane.after.started.Format(time.RFC3339Nano), lane.after.octets, lane.portIDs)
			projection := traffic.Projection
			t.Logf("projected samples=%d, bytes affected=%s rerouted=%s unrouted=%s unresolved=%s",
				projection.Samples, projection.AffectedBytes, projection.ReroutedBytes,
				projection.UnroutedBytes, projection.UnresolvedBytes)
			for _, port := range projection.Ports {
				t.Logf("projected port: %+v", port.Current)
			}
			logTransferStockFlowCaptures(t, st, *lane, links[0].index)
		}
	}()
	shipped.Await(t, "shipped what-if projects the closed signed traffic window", 40*time.Second, func() bool {
		status, traffic = readFailureLabPrediction(t, st, lane.reg.cookie, input)
		return status == http.StatusOK && traffic.Status == "projected" && traffic.Projection.Complete
	})
	lab.docker(t, "stop", "-t", "2", lane.exporter)
	wantBytes := strconv.Itoa(bytes)
	if traffic.ContextId != lane.reg.contextID || traffic.UnattributedRows != 0 || traffic.FlowRecords == 0 ||
		traffic.Projection.AffectedBytes != wantBytes || traffic.Projection.ReroutedBytes != wantBytes {
		t.Fatalf("the prediction did not move only the lane's original %s bytes: %+v", wantBytes, traffic)
	}
	for _, port := range traffic.Projection.Ports {
		if port.InterfaceId == lane.portIDs[1] && port.Direction == "out" && port.Current.AddedBps != "0" {
			return port.Current
		}
	}
	t.Fatalf("the prediction did not add load to the surviving egress %s", lane.portIDs[1])
	return sdk.TopologyFailurePortLoad{}
}

func awaitFailureLabPoll(t *testing.T, lane transferStockLane, links [2]roleRouterLink, after time.Time) transferStockPoll {
	t.Helper()
	var poll transferStockPoll
	shipped.Await(t, "current signed counter poll after the lab boundary", 40*time.Second, func() bool {
		var err error
		poll, err = readTransferStockPoll(lane, links, after, time.Now(), true)
		if err != nil {
			t.Fatal(err)
		}
		return !poll.started.IsZero()
	})
	return poll
}

func failureLabWhatIf(source, window transferStockLane, local, peer string) map[string]any {
	return map[string]any{
		"target":     topology.EdgeID("device:"+local, topology.EdgePhysical, "device:"+peer),
		"context_id": source.reg.contextID, "failure_interface_id": source.portIDs[0],
		"traffic_from": window.before.started.Format(time.RFC3339Nano), "traffic_to": window.after.started.Format(time.RFC3339Nano),
		"maximum_poll_gap": "40s",
	}
}

func readFailureLabPrediction(t *testing.T, st *shipped.Stack, cookie string, request map[string]any) (int, sdk.TopologyFailureTraffic) {
	t.Helper()
	code, raw := st.Do(t, cookie, http.MethodPost, "/v1/topology/whatif", request)
	var result struct{ Traffic sdk.TopologyFailureTraffic }
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("decode the topology prediction: %v", err)
		}
	}
	return code, result.Traffic
}

func assertFailureLabScope(t *testing.T, st *shipped.Stack, own, sibling transferStockLane, local, peer string) {
	t.Helper()
	code, _ := readFailureLabPrediction(t, st, own.reg.cookie, failureLabWhatIf(sibling, sibling, local, peer))
	if code != http.StatusNotFound && code != http.StatusForbidden {
		t.Fatalf("sibling routing context or failure interface was admitted: HTTP %d", code)
	}
	code, empty := readFailureLabPrediction(t, st, own.reg.cookie, failureLabWhatIf(own, sibling, local, peer))
	if code != http.StatusOK || empty.ContextId != own.reg.contextID || empty.FlowRecords != 0 || empty.Projection.ReroutedBytes != "0" {
		t.Fatalf("sibling's private original flowed into an empty owner window: HTTP %d %+v", code, empty)
	}
}

func waitFailureLabPath(t *testing.T, lab *routingLab, link roleRouterLink) {
	t.Helper()
	shipped.Await(t, "the lab kernel selects the surviving physical link", 20*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		raw, err := exec.CommandContext(ctx, "docker", "exec", lab.container("rtr-a"), "ip", "-j", "-4", "route", "get", transferStockAddress).Output()
		var paths []struct {
			Gateway string `json:"gateway"`
			Device  string `json:"dev"`
		}
		return err == nil && json.Unmarshal(raw, &paths) == nil && len(paths) == 1 &&
			paths[0].Gateway == link.peerIP && paths[0].Device == link.iface
	})
}

func measureFailureLabSurvivor(t *testing.T, lab *routingLab, link roleRouterLink, packetCount int, span time.Duration) (rate, capacity *big.Rat) {
	t.Helper()
	installRoutingLabWorkload(t, lab, packetCount, transferStockPayload, "edge", "rrc")
	readPortValue := func(field string) uint64 {
		t.Helper()
		raw := lab.docker(t, "exec", lab.container("rtr-a"), "cat", "/sys/class/net/"+link.iface+"/"+field)
		value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			t.Fatalf("read surviving kernel %s: %v", field, err)
		}
		return value
	}
	speed := readPortValue("speed")
	if speed == 0 {
		t.Fatal("the surviving kernel interface did not report a speed")
	}
	before, started := readPortValue("statistics/tx_bytes"), time.Now()
	sendRoutingLabPayload(t, lab, "rrc", lab.ip["rrc"], func(counts []byte) { t.Logf("failover receiver: %s", counts) })
	if t.Failed() {
		t.FailNow()
	}
	if wait := time.Until(started.Add(span)); wait > 0 {
		time.Sleep(wait)
	}
	after, elapsed := readPortValue("statistics/tx_bytes"), time.Since(started)
	if after <= before || after-before < uint64(packetCount)*uint64(transferStockPayload+28) {
		t.Fatal("the surviving kernel interface did not transmit the independent receiver's full payload")
	}
	if readPortValue("speed") != speed {
		t.Fatal("surviving kernel speed changed while measuring the replay")
	}
	return transferStockRate(after-before, elapsed), new(big.Rat).Mul(new(big.Rat).SetUint64(speed), big.NewRat(1_000_000, 1))
}

func assertFailureLabUtilization(t *testing.T, prediction sdk.TopologyFailurePortLoad, measured, physicalCapacity *big.Rat) {
	t.Helper()
	projected, ok := new(big.Rat).SetString(prediction.ProjectedBps)
	capacity, capacityOK := new(big.Rat).SetString(prediction.CapacityBps)
	if !ok || !capacityOK || projected.Sign() <= 0 || capacity.Sign() <= 0 || measured.Sign() <= 0 {
		t.Fatalf("comparison requires positive measured and projected load with a known physical speed: %+v", prediction)
	}
	if capacity.Cmp(physicalCapacity) != 0 {
		t.Fatalf("the projection used %s bps but the surviving kernel link reports %s bps", capacity, physicalCapacity)
	}
	predictedUtilization, haveUtilization := new(big.Rat).SetString(prediction.UtilizationRatio)
	if !haveUtilization || predictedUtilization.Cmp(new(big.Rat).Quo(projected, physicalCapacity)) != 0 {
		t.Fatalf("the reported utilization does not match its projected rate and physical speed: %+v", prediction)
	}
	gap := new(big.Rat).Abs(new(big.Rat).Sub(projected, measured))
	utilizationGap := new(big.Rat).Quo(gap, physicalCapacity)
	relativeGap := new(big.Rat).Quo(gap, measured)
	t.Logf("survivor utilization: predicted=%s measured=%s gap=%s percentage points, %s relative percent",
		predictedUtilization.FloatString(8), new(big.Rat).Quo(measured, physicalCapacity).FloatString(8),
		new(big.Rat).Mul(utilizationGap, big.NewRat(100, 1)).FloatString(8),
		new(big.Rat).Mul(relativeGap, big.NewRat(100, 1)).FloatString(2))
	if utilizationGap.Cmp(big.NewRat(5, 100)) > 0 || relativeGap.Cmp(big.NewRat(5, 100)) > 0 {
		t.Fatal("the prediction differs from independent surviving-link utilization by more than five points or five percent relative")
	}
}

func awaitFailureLabLinks(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, routers []failureLabRouter, own, sibling []string) {
	t.Helper()
	pool := st.ApplicationReadPool(t)
	registry := store.NewEntityRegistry(pool)
	counters := store.NewDeviceCounterCaptures(pool)
	scope := entity.Scope{TenantID: reg.tenantID, ContextID: reg.contextID}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(scope.TenantID))
	var last error
	defer func() {
		if t.Failed() && last != nil {
			t.Logf("reciprocal physical link lookup: %v", last)
		}
	}()
	shipped.Await(t, "current kernel-derived physical links in the tenant's routing context", 45*time.Second, func() bool {
		var current []store.ClientReportPhysicalLink
		fromDevices := make(map[string]string)
		last = tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			current, err = registry.CurrentPhysicalLinksInContext(ctx, sc, scope, 1<<20,
				func(context.Context, entity.ContextRecord, string, string) error { return nil })
			if err != nil {
				return err
			}
			for _, link := range current {
				// Physical receipts are anchored to a local interface and a
				// remote device. Read the local parent through its current
				// authenticated counter binding.
				port, err := counters.CurrentInterfaceInScope(ctx, sc, scope, link.FromEntityID)
				if err != nil {
					return err
				}
				if port.InterfaceID != link.FromEntityID || port.IfIndex != link.LocalIfIndex {
					return fmt.Errorf("the physical receipt no longer matches its original interface")
				}
				fromDevices[link.FromEntityID] = port.Source.DeviceID
			}
			return nil
		})
		if last != nil {
			return false
		}
		for _, item := range current {
			if item.TenantID != scope.TenantID || item.ContextID != scope.ContextID {
				t.Fatal("the physical link left its owning tenant context")
			}
			for _, foreign := range sibling {
				if fromDevices[item.FromEntityID] == foreign || item.ToEntityID == foreign {
					t.Fatal("the physical link references a sibling tenant device")
				}
			}
		}
		for i := 1; i < len(routers); i++ {
			local, peer := routers[0].ports[i-1], routers[i].ports[0]
			if !containsFailureLabLink(current, fromDevices, own[0], own[i], local, peer) ||
				!containsFailureLabLink(current, fromDevices, own[i], own[0], peer, local) {
				last = fmt.Errorf("missing current reciprocal link between %s and %s (saw %d current links)",
					routers[0].name, routers[i].name, len(current))
				return false
			}
		}
		return true
	})
}

func containsFailureLabLink(links []store.ClientReportPhysicalLink, fromDevices map[string]string, fromID, toID string, from, to failureLabPort) bool {
	for _, link := range links {
		if fromDevices[link.FromEntityID] == fromID && link.ToEntityID == toID && link.LocalIfIndex == from.Index &&
			link.LocalPort == from.Name && link.RemotePort == to.Name && link.Chassis == to.MAC {
			return true
		}
	}
	return false
}

// Read the two ends independently. The SNMP fixture publishes the observed
// cable mapping as CDP rows. Its counters still come from the live kernel.
func readFailureLabPort(t *testing.T, lab *routingLab, router, local, remote string) failureLabPort {
	t.Helper()
	container := lab.container(router)
	raw := lab.docker(t, "exec", container, "ip", "-j", "-4", "route", "get", remote, "from", local)
	var paths []struct {
		Device  string `json:"dev"`
		Gateway string `json:"gateway"`
	}
	if err := json.Unmarshal([]byte(raw), &paths); err != nil || len(paths) != 1 || paths[0].Gateway != "" || paths[0].Device == "" {
		t.Fatalf("%s does not reach its observed neighbor on a directly connected port: %s", router, raw)
	}
	raw = lab.docker(t, "exec", container, "ip", "-j", "link", "show", "dev", paths[0].Device)
	var ports []failureLabPort
	if err := json.Unmarshal([]byte(raw), &ports); err != nil || len(ports) != 1 || ports[0].Index == 0 || ports[0].Name != paths[0].Device {
		t.Fatalf("%s did not report one live kernel port for its neighbor: %s", router, raw)
	}
	mac, err := net.ParseMAC(ports[0].MAC)
	if err != nil || len(mac) != 6 {
		t.Fatalf("%s returned an invalid Ethernet address for %s", router, ports[0].Name)
	}
	ports[0].MAC = mac.String()
	return ports[0]
}

func failureLabNeighborRows(local, peer failureLabPort, peerAddress string) string {
	return fmt.Sprintf(`override .1.3.6.1.4.1.9.9.23.1.2.1.1.4.%d.1 octet_str %q
override .1.3.6.1.4.1.9.9.23.1.2.1.1.6.%d.1 octet_str %q
override .1.3.6.1.4.1.9.9.23.1.2.1.1.7.%d.1 octet_str %q
`, local.Index, peerAddress, local.Index, peer.MAC, local.Index, peer.Name)
}
