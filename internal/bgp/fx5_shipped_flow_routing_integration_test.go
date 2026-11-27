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
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

const fx5FlowDomain = 9
const fx5FlowPort = 26443

type fx5FlowGolden struct {
	prefix, provenance, rpki string
	origin                   uint32
}

type fx5FlowExpectation struct {
	fx5FlowGolden
	bytes string
}

// Each tenant imports a different original public path for the same range.
// There are no BMP assignments. The public label and each independent IPFIX
// row must survive the shipped collector, bus, stores and authenticated API.
func TestFX5ShippedPublicFallbackWithoutBMPRouter(t *testing.T) {
	if runtime.GOOS != "linux" {
		testsupport.SkipOrFatal(t, "the shipped IPFIX proof requires a Linux route to the owned FRR bridge")
	}
	lab := startRoutingLab(t)
	st := shipped.Start(t, shipped.Options{Name: "fx5-public-fallback", TenantBand: 4})
	first := registerEdgeFlowEvidence(t, st, lab.ip["rtr-a"])
	second := registerEdgeFlowEvidence(t, st, lab.ip["rtr-a"], registerSecondRouterTenant(t, st, first))
	lanes := []edgeFlowRegistration{first, second}
	expected := make([][]fx5FlowGolden, len(lanes))
	const source = "ris/mrt_table_dump_v2/rrc00"
	for i, lane := range lanes {
		origin := uint32(64497 + i)
		requireRoleSourceBinding(t, st, lane, map[string]string{"agent_id": lane.agentID, "source_kind": "public_bgp",
			"source_ref": source, "context_id": lane.contextID})
		client, err := agent.DialEntityEvidence(st.AgentAddr, lane.certFile, lane.keyFile, lane.caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		wire := fx5PublicMRT(t, origin)
		result, err := client.ImportPublicMRT(t.Context(), bytes.NewReader(wire), agent.DefaultPublicMRTOptions(source))
		if err != nil || result.SnapshotID == "" || result.Bytes != int64(len(wire)) {
			t.Fatalf("lane %d original public MRT import: %+v %v", i, result, err)
		}
		pool := st.ApplicationReadPool(t)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.tenantID))
		err = tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			var bmp int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_source_contexts WHERE tenant_id=$1 AND source_kind='bmp_peer'`, lane.tenantID).Scan(&bmp); err != nil {
				return err
			}
			if bmp != 0 {
				return fmt.Errorf("public-only tenant has %d BMP assignments", bmp)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		expected[i] = []fx5FlowGolden{{prefix: prefixA, provenance: "public_ris", rpki: "unknown", origin: origin}}
	}
	proveFX5ShippedFlowGoldens(t, st, lab, lanes, expected)
}

// The original wire format is a bounded synthetic TABLE_DUMP_V2 recording.
// Only the clock and the distinct tenant origin vary between runs.
func fx5PublicMRT(t *testing.T, origin uint32) []byte {
	t.Helper()
	stamp := routingGoldenWord(t, time.Now().Add(-time.Second).Unix())
	record := func(subtype uint16, body []byte) []byte {
		return append(routingGoldenWire(t, stamp, uint16(13), subtype, routingGoldenWord(t, int64(len(body)))), body...)
	}
	peer := routingGoldenWire(t, [4]byte{192, 0, 2, 1}, uint16(0), uint16(1), uint8(2),
		[4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 1}, uint32(64496))
	attrs := routingGoldenWire(t, []byte{0x40, 1, 1, 0, 0x40, 2, 10, 2, 2},
		uint32(64496), origin, []byte{0x40, 3, 4, 192, 0, 2, 1})
	rib := routingGoldenWire(t, uint32(1), []byte{24, 203, 0, 113}, uint16(1), uint16(0), stamp,
		routingGoldenHalf(t, len(attrs)), attrs)
	return append(record(1, peer), record(2, rib)...)
}

func proveFX5ShippedFlowGoldens(t *testing.T, st *shipped.Stack, lab *routingLab, lanes []edgeFlowRegistration, expected [][]fx5FlowGolden) {
	t.Helper()
	exporter := netip.MustParseAddr(lab.ip["rtr-a"])
	from := time.Now().Add(-2 * time.Second)
	rows := make([]map[string]fx5FlowExpectation, len(lanes))
	for i, lane := range lanes {
		requireRoleSourceBinding(t, st, lane, map[string]string{"agent_id": lane.agentID, "source_kind": "flow_exporter",
			"source_ref": exporter.String(), "context_id": lane.contextID, "anchor_entity_id": lane.deviceID})
		destination := startShippedRouterFlow(t, st, lab, lane, exporter.String())
		warm := netip.MustParsePrefix(expected[i][0].prefix).Addr().Next()
		sendOwnedRouterGolden(t, lab, destination, fx5IPFIX(t, warm, fx5FlowPort-1, 1, 0))
		awaitFX5ExporterBinding(t, st, lane, exporter)
		rows[i] = make(map[string]fx5FlowExpectation, len(expected[i]))
		for n, golden := range expected[i] {
			address := netip.MustParsePrefix(golden.prefix).Addr().Next()
			if i == 1 {
				address = address.Next()
			}
			octets := uint32(1000 * (i + 1) * (n + 1))
			rows[i][address.String()] = fx5FlowExpectation{golden, strconv.FormatUint(uint64(octets), 10)}
			sendOwnedRouterGolden(t, lab, destination, fx5IPFIX(t, address, fx5FlowPort, octets, uint32(n+1)))
		}
	}
	assertFX5ExplorerFlowGoldens(t, st, lanes, from, rows)
}

func awaitFX5ExporterBinding(t *testing.T, st *shipped.Stack, lane edgeFlowRegistration, exporter netip.Addr) {
	t.Helper()
	pool := st.ApplicationReadPool(t)
	reader := store.NewInterfaceRoleInputs(pool)
	scope := entity.Scope{TenantID: lane.tenantID, ContextID: lane.contextID}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.tenantID))
	shipped.Await(t, "original IPFIX exporter has an authenticated tenant binding", 30*time.Second, func() bool {
		var ready bool
		err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			rows, err := reader.FlowBindingsInScope(ctx, sc, scope, entity.InterfaceRolePolicyBudget{MemoryBytes: 32 << 20, WorkUnits: 32 << 20})
			for _, row := range rows {
				if row.Scope == scope && row.AgentID == lane.agentID && row.RouterID == lane.deviceID &&
					row.Exporter == exporter && row.Protocol == flow.ProtoIPFIX && row.Domain == fx5FlowDomain && row.ValidUntil.After(time.Now()) {
					ready = true
				}
			}
			return err
		})
		return err == nil && ready
	})
}

func fx5IPFIX(t *testing.T, destination netip.Addr, port uint16, octets, sequence uint32) []byte {
	t.Helper()
	fields := []uint16{8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 4, 2, 4, 152, 8, 153, 8}
	var addresses []byte
	if destination.Is4() {
		addresses = routingGoldenWire(t, [4]byte{198, 51, 100, 1}, destination.As4())
	} else {
		fields[0], fields[1], fields[2], fields[3] = 27, 16, 28, 16
		addresses = routingGoldenWire(t, netip.MustParseAddr("2001:db8:ffff::1").As16(), destination.As16())
	}
	now := time.Now()
	template := routingGoldenWire(t, uint16(256), routingGoldenHalf(t, len(fields)/2), fields)
	data := routingGoldenWire(t, addresses, uint16(41001), port, uint8(17), octets, uint32(1),
		uint64(now.Add(-time.Second).UnixMilli()), uint64(now.UnixMilli()))
	return routingGoldenWire(t, uint16(10), routingGoldenHalf(t, 24+len(template)+len(data)),
		routingGoldenWord(t, now.Unix()), sequence, uint32(fx5FlowDomain),
		uint16(2), routingGoldenHalf(t, 4+len(template)), template,
		uint16(256), routingGoldenHalf(t, 4+len(data)), data)
}

func assertFX5ExplorerFlowGoldens(t *testing.T, st *shipped.Stack, lanes []edgeFlowRegistration, from time.Time,
	expected []map[string]fx5FlowExpectation) {
	t.Helper()
	plan := flow.QueryPlan{From: from, To: time.Now().Add(30 * time.Second), View: "table", DataSeries: "raw",
		GroupBy: []string{"dst_addr", "dst_bgp_prefix", "dst_bgp_origin_as", "dst_bgp_provenance", "dst_bgp_rpki"},
		Filter:  &flow.QueryFilterGroup{Mode: "include", Match: "all", Conditions: []flow.QueryPredicate{{Field: "dst_port", Op: flow.QueryEqual, Values: []string{strconv.Itoa(fx5FlowPort)}}}},
		Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "flows", Calculation: "total"}}}
	last := make([][]byte, len(lanes))
	defer func() {
		if t.Failed() {
			for i, body := range last {
				t.Logf("lane %d last FX-5 Explorer response: %.1600s", i, body)
			}
		}
	}()
	shipped.Await(t, "only the tenant's original flow routes, provenance and validation", time.Minute, func() bool {
		ready := true
		for i, lane := range lanes {
			code, body := st.Do(t, lane.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
			last[i] = body
			ready = fx5ExplorerMatches(code, body, expected[i]) && ready
		}
		return ready
	})
}

func fx5ExplorerMatches(code int, body []byte, addresses map[string]fx5FlowExpectation) bool {
	var result struct {
		Flow *flowstore.PlanResult `json:"flow"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Flow == nil || len(result.Flow.Rows) != len(addresses) {
		return false
	}
	seen := make(map[string]bool, len(addresses))
	for _, row := range result.Flow.Rows {
		address := row.Group["dst_addr"]
		want, ok := addresses[address]
		if !ok || seen[address] || row.Group["dst_bgp_prefix"] != want.prefix ||
			row.Group["dst_bgp_origin_as"] != strconv.FormatUint(uint64(want.origin), 10) ||
			row.Group["dst_bgp_provenance"] != want.provenance || row.Group["dst_bgp_rpki"] != want.rpki ||
			row.Metrics["bytes:total"] != want.bytes || row.Metrics["flows:total"] != "1" {
			return false
		}
		seen[address] = true
	}
	return true
}
