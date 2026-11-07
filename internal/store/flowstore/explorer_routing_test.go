// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingQueryProjectionKeepsWholeSharedPathsAndOriginalTenantKeys(t *testing.T) {
	const count = 50_000
	const tenant = "11111111-1111-4111-8111-111111111111"
	const contextID = "33333333-3333-4333-8333-333333333333"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	at := time.Unix(1700000000, 123456789).UTC()
	var path strings.Builder
	for i := range 65_537 {
		if i != 0 {
			path.WriteByte(' ')
		}
		path.WriteString(strconv.FormatUint(uint64(i+1), 10))
	}
	path.WriteString(" 4294967295")
	encoded, err := json.Marshal([]string{path.String()})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{
		"src_bgp_provenance": "router_selected", "dst_bgp_provenance": "router_selected",
		"src_bgp_prefix": "203.0.113.0/24", "dst_bgp_prefix": "2001:db8::/32",
		"src_bgp_as_paths": string(encoded), "dst_bgp_as_paths": string(encoded),
		"src_bgp_origin_as": "4294967295", "dst_bgp_origin_as": "4294967295",
		"src_bgp_first_transit_as": "1", "dst_bgp_first_transit_as": "1",
		"src_bgp_next_hop_as": "", "dst_bgp_next_hop_as": "",
		"src_bgp_rpki": "unknown", "dst_bgp_rpki": "unknown",
	}
	rows := make([]RoutingProjection, count)
	var last Row
	for i := range rows {
		var digest [32]byte
		binary.BigEndian.PutUint64(digest[:8], uint64(i+1))
		input := entity.FlowCaptureInput{Exporter: netip.MustParseAddr("192.0.2.1"), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("2001:db8::1"), Protocol: "ipfix", Domain: ^uint32(0)}
		key, err := entity.FlowCaptureKey(tenant, "routing-flow", digest, input)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = RoutingProjection{Scope: entity.Scope{TenantID: tenant, ContextID: contextID}, Key: key, Clock: at.UnixNano(), Fields: fields, SourceIDs: []string{"routing-view/current-source-and-origin"}, FactsID: [32]byte{31: 1}}
		if i == count-1 {
			last = Row{TenantID: tenant, AgentID: "routing-flow", Exporter: input.Exporter.String(), Protocol: input.Protocol, ObsDomain: input.Domain, SrcAddr: input.Source.String(), DstAddr: input.Destination.String(), RawFlowDigest: hex.EncodeToString(digest[:]), RoutingCaptureKey: hex.EncodeToString(key[:]), RoutingCapturedUnixNanos: at.UnixNano()}
		}
	}
	data, err := newRoutingQueryData(ctx, tenant, at, rows, 64<<20)
	if err != nil || len(data.byKey) != count {
		t.Fatal("complete routing query projection lost shared full paths or original references", err)
	}
	if len(data.facts) != 1 {
		t.Fatal("routing query projection duplicated identical source facts", len(data.facts))
	}
	external, err := data.externalData(ctx, tenant, 64<<20)
	if err != nil || len(external) != 2 {
		t.Fatal("complete routing projection lost its reference or fact transport", err)
	}
	var references int
	decoder := json.NewDecoder(bytes.NewReader(external[0].rows))
	for decoder.More() {
		var reference struct {
			Tenant string `json:"routing_ref_tenant"`
			Clock  string `json:"routing_clock"`
		}
		if err := decoder.Decode(&reference); err != nil || reference.Tenant != tenant || reference.Clock != strconv.FormatInt(at.UnixNano(), 10) {
			t.Fatal("routing reference transport changed exact clock or tenant", err)
		}
		references++
	}
	if references != count || bytes.Count(external[1].rows, []byte{'\n'}) != 1 {
		t.Fatal("routing projection transport duplicated full facts or lost original references", references)
	}
	if parts, err := data.externalData(ctx, tenant, 1024); !errors.Is(err, ErrExplorerBudget) || parts != nil {
		t.Fatal("routing projection transport returned a truncated admission prefix", err)
	}
	conflict := append([]RoutingProjection(nil), rows[:2]...)
	conflict[1].Fields = maps.Clone(fields)
	conflict[1].Fields["src_bgp_origin_as"] = "64500"
	if partial, err := newRoutingQueryData(ctx, tenant, at, conflict, 64<<20); !errors.Is(err, ErrRoutingQueryScope) || partial != nil {
		t.Fatal("routing query source hint replaced complete verified fields", err)
	}
	if got := data.valueForRow(last, "src_bgp_as_paths"); got != string(encoded) || data.valueForRow(last, "src_bgp_origin_as") != "4294967295" {
		t.Fatal("routing query projection truncated the complete path or full ASN")
	}
	fields["src_bgp_as_paths"] = "mutated caller path"
	if data.valueForRow(last, "src_bgp_as_paths") != string(encoded) {
		t.Fatal("routing query projection retained mutable caller authority")
	}
	plan := flow.QueryPlan{GroupBy: []string{"src_bgp_as_paths"}}
	if err := validatePlanRouting(ctx, PlanQuery{TenantID: tenant, Routing: data}, plan); err != nil {
		t.Fatal(err)
	}
	if err := validatePlanRouting(ctx, PlanQuery{TenantID: tenant}, plan); !errors.Is(err, ErrRoutingQueryScope) {
		t.Fatal("routing query accepted absent current source authority", err)
	}
	last.TenantID = "22222222-2222-4222-8222-222222222222"
	if data.valueForRow(last, "src_bgp_as_paths") != "" || data.valueForRow(last, "src_bgp_provenance") != "unavailable" {
		t.Fatal("routing query projection exposed another tenant's path")
	}
}
