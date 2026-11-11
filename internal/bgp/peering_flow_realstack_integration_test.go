// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// Actual FRR-selected RIB, source-bound shipped collectors, evidence mTLS,
// Kafka, ClickHouse, current Postgres/RLS and the public Explorer. The UDP
// datagrams below are protocol goldens emitted from the owned router network
// namespace, not claims of hardware export or actual forwarding. This
// field leg does not replace physical senders or peering p95 proof.
func proveFRRSelectedGoldenFlowFields(t *testing.T, st *shipped.Stack, lab *routingLab, own, sibling edgeFlowRegistration, nextHops []netip.Addr) {
	t.Helper()
	// Next-hop ASN needs independent current neighbor evidence. Establish it
	// before the first immutable flow capture; never warm up by discarding a
	// flow or infer this ASN from the selected AS path.
	pool := st.ApplicationReadPool(t)
	peers := store.NewInterfaceRoleInputs(pool)
	wanted := map[netip.Addr]bool{}
	for _, address := range nextHops {
		wanted[address] = true
	}
	var lastPeers []store.InterfaceRolePeerInput
	var lastPeerError error
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("independent router neighbors: wanted=%v current=%+v error=%v", nextHops, lastPeers, lastPeerError)
		}
	})
	shipped.Await(t, "current independently authenticated router neighbors before golden ingestion", time.Minute, func() bool {
		seen := map[netip.Addr]bool{}
		valid := true
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(own.tenantID))
		err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			rows, err := peers.RouterPeersInScope(ctx, sc, entity.Scope{TenantID: own.tenantID, ContextID: own.contextID}, own.deviceID, entity.InterfaceRolePolicyBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20})
			lastPeers = rows
			if err != nil {
				return err
			}
			for _, peer := range rows {
				if wanted[peer.Address] {
					if peer.ASN != edgeASN || !peer.ValidUntil.After(time.Now()) {
						valid = false
						return nil
					}
					seen[peer.Address] = true
				}
			}
			return nil
		})
		lastPeerError = err
		return err == nil && valid && len(seen) == len(wanted)
	})
	exporter := lab.ip["rtr-a"]
	listeners := startShippedRouterFlowProtocols(t, st, lab, own, exporter, []string{"NETFLOW", "IPFIX", "SFLOW"})
	started := time.Now().UTC()
	for _, packet := range routingProtocolGoldens(t, exporter) {
		host, port, err := net.SplitHostPort(listeners[packet.protocol])
		if err != nil {
			t.Fatal(err)
		}
		// Arguments remain positional, including the owned loopback/bridge
		// destination; fixture bytes are stdin and never shell source.
		command := exec.Command("docker", "exec", "-i", lab.container("rtr-a"), "bash", "-c", `cat > /dev/udp/"$1"/"$2"`, "owned-flow-golden", host, port)
		command.Stdin = bytes.NewReader(packet.wire)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("owned router protocol golden failed: %v %.400s", err, out)
		}
	}
	paths, err := json.Marshal([]string{path(edgeASN, originA)})
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{}
	for _, side := range []string{"src", "dst"} {
		expected[side+"_bgp_prefix"] = prefixA
		expected[side+"_bgp_as_paths"] = string(paths)
		expected[side+"_bgp_origin_as"] = strconv.Itoa(originA)
		expected[side+"_bgp_first_transit_as"] = strconv.Itoa(edgeASN)
		expected[side+"_bgp_next_hop_as"] = strconv.Itoa(edgeASN)
		expected[side+"_bgp_rpki"] = "unknown" // No validator source is configured in this source leg.
		expected[side+"_bgp_provenance"] = "router_selected"
	}
	fields := []string{}
	for _, side := range []string{"src", "dst"} {
		for _, field := range []string{"prefix", "as_paths", "origin_as", "first_transit_as", "next_hop_as", "rpki", "provenance"} {
			fields = append(fields, side+"_bgp_"+field)
		}
	}
	wantBytes := map[string]string{"netflow5/ipv4": "1000", "netflow9/ipv4": "2000", "netflow9/ipv6": "4000", "ipfix/ipv4": "3000", "ipfix/ipv6": "5000", "sflow5/ipv4": "5800", "sflow5/ipv6": "7800"}
	for start := 0; start < len(fields); start += 6 {
		selected := fields[start:min(start+6, len(fields))]
		plan := flow.QueryPlan{From: started.Add(-time.Minute), To: time.Now().Add(time.Minute), View: "table", GroupBy: append([]string{"protocol", "net_type"}, selected...), Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "flows", Calculation: "total"}}}
		var last string
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("original protocol routing field diagnostic: %.1500s", last)
			}
		})
		shipped.Await(t, "original router paths on every shipped protocol golden", 60*time.Second, func() bool {
			code, body := st.Do(t, own.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
			var out struct {
				Flow *flowstore.PlanResult `json:"flow"`
			}
			last = string(body)
			if code != http.StatusOK || json.Unmarshal(body, &out) != nil || out.Flow == nil || len(out.Flow.Rows) != len(wantBytes) {
				return false
			}
			seen := map[string]bool{}
			for _, row := range out.Flow.Rows {
				protocol := row.Group["protocol"] + "/" + row.Group["net_type"]
				if wantBytes[protocol] == "" || seen[protocol] || row.Metrics["bytes:total"] != wantBytes[protocol] || row.Metrics["flows:total"] != "1" {
					return false
				}
				seen[protocol] = true
				for _, field := range selected {
					want := expected[field]
					if row.Group["net_type"] == "ipv6" && (field == "src_bgp_prefix" || field == "dst_bgp_prefix") {
						want = "2001:db8:5000::/48"
					}
					if row.Group[field] != want {
						last = protocol + " " + field + " got=" + row.Group[field] + " expected=" + want
						return false
					}
				}
			}
			return true
		})
		code, body := st.Do(t, sibling.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
		var out struct {
			Flow *flowstore.PlanResult `json:"flow"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil || out.Flow == nil || len(out.Flow.Rows) != 0 {
			t.Fatal("sibling tenant's real RIB authorized another tenant's protocol traffic", code)
		}
	}
	t.Log("real-integration: actual selected FRR source joined to shipped NetFlow5/9, IPFIX and sFlow5 protocol goldens; fourteen routing fields, exact sampled counters and sibling empty-flow control; generated dual-family datagrams and no validator/peering/hardware-forwarding claim")
}

type routingProtocolGolden struct {
	protocol string
	wire     []byte
}

func routingGoldenWire(t *testing.T, values ...any) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&out, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

func routingGoldenHalf(t *testing.T, value int) uint16 {
	t.Helper()
	if value < 0 || value > 65535 {
		t.Fatal("golden protocol length exceeds its 16-bit wire field")
		return 0
	}
	return uint16(value)
}

func routingGoldenWord(t *testing.T, value int64) uint32 {
	t.Helper()
	if value < 0 || value > 4294967295 {
		t.Fatal("golden protocol value exceeds its 32-bit wire field")
		return 0
	}
	return uint32(value)
}

func routingProtocolGoldens(t *testing.T, exporter string) []routingProtocolGolden {
	t.Helper()
	source, destination := [4]byte{203, 0, 113, 1}, [4]byte{203, 0, 113, 2}
	var source6, destination6 [16]byte
	copy(source6[:], net.ParseIP("2001:db8:5000::1").To16())
	copy(destination6[:], net.ParseIP("2001:db8:5000::2").To16())
	now := time.Now()
	seconds := routingGoldenWord(t, now.Unix())
	nf5 := routingGoldenWire(t, uint16(5), uint16(1), uint32(60000), seconds, routingGoldenWord(t, int64(now.Nanosecond())), uint32(0), uint8(0), uint8(0), uint16(0))
	nf5 = append(nf5, routingGoldenWire(t, source, destination, [4]byte{}, uint16(1), uint16(2), uint32(10), uint32(1000), uint32(59000), uint32(59900), uint16(41001), uint16(443), uint8(0), uint8(0x18), uint8(6), uint8(0), uint16(64512), uint16(64513), uint8(24), uint8(24), uint16(0))...)
	template := func(set uint16, ipv6 bool) []byte {
		id := uint16(256)
		fields := []uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 4, 2, 4}
		if ipv6 {
			id++
			fields[0], fields[1], fields[2], fields[3] = 27, 16, 28, 16
		}
		body := routingGoldenWire(t, id, uint16(7), fields)
		return append(routingGoldenWire(t, set, routingGoldenHalf(t, 4+len(body))), body...)
	}
	data := func(n uint16, ipv6 bool) []byte {
		id := uint16(256)
		body := routingGoldenWire(t, source, destination)
		if ipv6 {
			id++
			body = routingGoldenWire(t, source6, destination6)
		}
		body = append(body, routingGoldenWire(t, uint16(41000)+n, uint16(443), uint8(6), uint32(n)*1000, uint32(n)*10)...)
		return append(routingGoldenWire(t, id, routingGoldenHalf(t, 4+len(body))), body...)
	}
	netflow := func(n uint16, sequence uint32, ipv6 bool) []byte {
		packet := append(routingGoldenWire(t, uint16(9), uint16(2), uint32(60000), seconds, sequence, uint32(7)), template(0, ipv6)...)
		return append(packet, data(n, ipv6)...)
	}
	ipfix := func(n uint16, sequence uint32, ipv6 bool) []byte {
		body := append(template(2, ipv6), data(n, ipv6)...)
		return append(routingGoldenWire(t, uint16(10), routingGoldenHalf(t, 16+len(body)), seconds, sequence, uint32(9)), body...)
	}
	tcp := routingGoldenWire(t, uint16(41004), uint16(443), uint32(1), uint32(0), uint8(0x50), uint8(0x10), uint16(8192), uint16(0), uint16(0))
	frame4 := append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0}, routingGoldenWire(t, uint8(0x45), uint8(0), uint16(40), uint16(1234), uint16(0), uint8(64), uint8(6), uint16(0), source, destination)...)
	frame4 = append(frame4, tcp...)
	frame6 := append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x86, 0xdd}, routingGoldenWire(t, uint32(0x60000000), routingGoldenHalf(t, len(tcp)), uint8(6), uint8(64), source6, destination6)...)
	frame6 = append(frame6, tcp...)
	var agent [4]byte
	address := net.ParseIP(exporter).To4()
	if address == nil {
		t.Fatal("golden exporter needs its actual owned IPv4 address")
	}
	copy(agent[:], address)
	sflow := func(frame []byte, sequence uint32) []byte {
		raw := append(routingGoldenWire(t, uint32(1), routingGoldenWord(t, int64(len(frame)+4)), uint32(4), routingGoldenWord(t, int64(len(frame)))), frame...)
		for len(raw)%4 != 0 {
			raw = append(raw, 0)
		}
		record := append(routingGoldenWire(t, uint32(1), routingGoldenWord(t, int64(len(raw)))), raw...)
		sample := append(routingGoldenWire(t, sequence, uint32(0x01000001), uint32(100), uint32(100), uint32(0), uint32(3), uint32(4), uint32(1)), record...)
		return append(routingGoldenWire(t, uint32(5), uint32(1), agent, uint32(0), sequence, uint32(1000), uint32(1), uint32(1), routingGoldenWord(t, int64(len(sample)))), sample...)
	}
	return []routingProtocolGolden{{"NETFLOW", nf5}, {"NETFLOW", netflow(2, 0, false)}, {"NETFLOW", netflow(4, 1, true)}, {"IPFIX", ipfix(3, 0, false)}, {"IPFIX", ipfix(5, 1, true)}, {"SFLOW", sflow(frame4, 1)}, {"SFLOW", sflow(frame6, 2)}}
}
