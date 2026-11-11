// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// Actual FRR-selected RIB, source-bound shipped collectors, evidence mTLS,
// Kafka, ClickHouse, current Postgres/RLS and the public Explorer. The UDP
// datagrams below are protocol goldens emitted from the owned router network
// namespace, not claims of hardware export or actual forwarding. This IPv4
// field leg does not replace dual-family physical senders or peering p95 proof.
func proveFRRSelectedGoldenFlowFields(t *testing.T, st *shipped.Stack, lab *routingLab, own, sibling edgeFlowRegistration) {
	t.Helper()
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
	wantBytes := map[string]string{"netflow5": "1000", "netflow9": "2000", "ipfix": "3000", "sflow5": "5800"}
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
				protocol := row.Group["protocol"]
				if wantBytes[protocol] == "" || seen[protocol] || row.Group["net_type"] != "ipv4" || row.Metrics["bytes:total"] != wantBytes[protocol] || row.Metrics["flows:total"] != "1" {
					return false
				}
				seen[protocol] = true
				for _, field := range selected {
					if row.Group[field] != expected[field] {
						last = protocol + " " + field + " got=" + row.Group[field] + " expected=" + expected[field]
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
	t.Log("real-integration: actual selected FRR source joined to shipped NetFlow5/9, IPFIX and sFlow5 protocol goldens; fourteen routing fields, exact sampled counters and sibling empty-flow control; generated datagrams/IPv4 and no validator/peering/hardware-forwarding claim")
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

func routingProtocolGoldens(t *testing.T, exporter string) []routingProtocolGolden {
	t.Helper()
	source, destination := [4]byte{203, 0, 113, 1}, [4]byte{203, 0, 113, 2}
	now := time.Now()
	seconds := uint32(now.Unix())                                                                                                                 //nolint:gosec // current protocol-fixture timestamp
	nf5 := routingGoldenWire(t, uint16(5), uint16(1), uint32(60000), seconds, uint32(now.Nanosecond()), uint32(0), uint8(0), uint8(0), uint16(0)) //nolint:gosec // current protocol-fixture nanoseconds
	nf5 = append(nf5, routingGoldenWire(t, source, destination, [4]byte{}, uint16(1), uint16(2), uint32(10), uint32(1000), uint32(59000), uint32(59900), uint16(41001), uint16(443), uint8(0), uint8(0x18), uint8(6), uint8(0), uint16(64512), uint16(64513), uint8(24), uint8(24), uint16(0))...)
	template := func(id uint16) []byte {
		body := routingGoldenWire(t, uint16(256), uint16(7), []uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 4, 2, 4})
		return append(routingGoldenWire(t, id, uint16(4+len(body))), body...) //nolint:gosec // fixed tiny template
	}
	data := func(n uint16) []byte {
		body := routingGoldenWire(t, source, destination, uint16(41000)+n, uint16(443), uint8(6), uint32(n)*1000, uint32(n)*10)
		return append(routingGoldenWire(t, uint16(256), uint16(4+len(body))), body...) //nolint:gosec // fixed tiny record
	}
	nf9 := append(routingGoldenWire(t, uint16(9), uint16(2), uint32(60000), seconds, uint32(0), uint32(7)), template(0)...)
	nf9 = append(nf9, data(2)...)
	body := append(template(2), data(3)...)
	ipfix := append(routingGoldenWire(t, uint16(10), uint16(16+len(body)), seconds, uint32(0), uint32(9)), body...) //nolint:gosec // fixed tiny datagram
	tcp := routingGoldenWire(t, uint16(41004), uint16(443), uint32(1), uint32(0), uint8(0x50), uint8(0x10), uint16(8192), uint16(0), uint16(0))
	frame := append([]byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0}, routingGoldenWire(t, uint8(0x45), uint8(0), uint16(40), uint16(1234), uint16(0), uint8(64), uint8(6), uint16(0), source, destination)...)
	frame = append(frame, tcp...)
	raw := append(routingGoldenWire(t, uint32(1), uint32(len(frame)+4), uint32(4), uint32(len(frame))), frame...) //nolint:gosec // fixed54-byte header
	for len(raw)%4 != 0 {
		raw = append(raw, 0)
	}
	record := append(routingGoldenWire(t, uint32(1), uint32(len(raw))), raw...) //nolint:gosec // fixed protocol fixture
	sample := append(routingGoldenWire(t, uint32(1), uint32(0x01000001), uint32(100), uint32(100), uint32(0), uint32(3), uint32(4), uint32(1)), record...)
	var agent [4]byte
	address := net.ParseIP(exporter).To4()
	if address == nil {
		t.Fatal("golden exporter needs its actual owned IPv4 address")
	}
	copy(agent[:], address)
	sflow := append(routingGoldenWire(t, uint32(5), uint32(1), agent, uint32(0), uint32(1), uint32(1000), uint32(1), uint32(1), uint32(len(sample))), sample...) //nolint:gosec // fixed protocol fixture
	return []routingProtocolGolden{{"NETFLOW", nf5}, {"NETFLOW", nf9}, {"IPFIX", ipfix}, {"SFLOW", sflow}}
}
