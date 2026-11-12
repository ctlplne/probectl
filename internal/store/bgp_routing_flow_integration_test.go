// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual application-role Postgres/RLS and registry writers. Protocol/source
// metadata is modeled here; actual FRR/flow wire belongs to the sender proof.
func TestRoutingFlowCaptureRequiresUniqueCurrentExporterAndKeepsTenantRoutes(t *testing.T) {
	f, changes, serials, input := newRoutingFlowCaptureFixture(t)
	read := func(lane int, value BGPRoutingFlowInput, budget BGPRoutingBudget) (BGPRoutingFlowLookup, error) {
		t.Helper()
		var got BGPRoutingFlowLookup
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			got, err = (BGPRouting{}).LookupFlowInScope(ctx, sc, value, budget)
			return err
		})
		return got, err
	}
	check := func(lane int) {
		t.Helper()
		got, err := read(lane, input, routingViewBudget())
		if err != nil || got.Owner.TenantID != f.tenants[lane] || got.Owner.RouterID != f.routerID || got.CapturedAt.IsZero() || got.Source.State != "router_selected" || got.Destination.State != "router_selected" || !reflect.DeepEqual(got.Source.Route.Paths, []BGPRoutingChange{changes[lane]}) || !reflect.DeepEqual(got.Destination.Route.Paths, got.Source.Route.Paths) {
			t.Fatal("current exporter lookup lost complete owned paths or crossed tenant", lane, got, err)
		}
		wantText := fmt.Sprintf("(64496) %d 64497 64497 {64500,64501}", 64496+lane)
		if len(got.Source.Fields) != 1 || len(got.Destination.Fields) != 1 || got.Source.Fields[0].ASPathText != wantText || got.Destination.Fields[0].ASPathText != wantText || got.Source.Fields[0].OriginAS != nil || got.Source.Fields[0].FirstTransitAS != nil {
			t.Fatal("current flow projection lost complete structured path or invented an endpoint", got, err)
		}
		if len(got.Source.NextHops) != 1 || len(got.Destination.NextHops) != 1 || got.Source.NextHops[0].ASN == nil || *got.Source.NextHops[0].ASN != uint32(65010+lane) || got.Destination.NextHops[0].ASN == nil || *got.Destination.NextHops[0].ASN != uint32(65010+lane) || len(got.Source.NextHops[0].Sources) != 1 {
			t.Fatal("next-hop AS lost current same-router neighbor evidence or crossed tenant", got, err)
		}
	}
	check(0)
	check(1)
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var observed, expired, checkedAt time.Time
		err := sc.Q.QueryRow(ctx, `UPDATE entity_evidence SET expires_at=clock_timestamp()-interval '1 microsecond'
 WHERE tenant_id=$1 AND alias_kind='bmp_peer_id' RETURNING observed_at,expires_at,clock_timestamp()`, f.tenants[0]).Scan(&observed, &expired, &checkedAt)
		if err == nil && (!expired.After(observed) || !expired.Before(checkedAt)) {
			t.Fatal("neighbor expiry fixture changed the observation or retained a live lease", observed, expired)
		}
		return err
	})
	if got, err := read(0, input, routingViewBudget()); err != nil || got.Source.State != "router_selected" || len(got.Source.NextHops) != 1 || got.Source.NextHops[0].ASN != nil || got.Source.Fields[0].ASPathText == "" {
		t.Fatal("expired neighbor retained next-hop AS or erased independent route evidence", got, err)
	}
	check(1)
	f.peerAtAddress(f.tenants[0], "2001:db8::1", 65010)
	check(0)
	missing := input
	missing.Destination = netip.MustParseAddr("198.51.100.1")
	if got, err := read(0, missing, routingViewBudget()); err != nil || got.Source.State != "router_selected" || got.Destination.State != "no_prefix" || got.Destination.Route.Paths != nil {
		t.Fatal("complete RIB absence erased another direction or invented a route", got, err)
	}
	for _, changed := range []BGPRoutingFlowInput{
		{Exporter: input.Exporter, Source: input.Source, Destination: input.Destination, Protocol: "sflow5", Domain: input.Domain},
		{Exporter: input.Exporter, Source: input.Source, Destination: input.Destination, Protocol: input.Protocol, Domain: 0},
	} {
		if got, err := read(0, changed, routingViewBudget()); !errors.Is(err, ErrBGPRoutingFlowSource) || got.Owner.RouterID != "" || got.Source.Route.Paths != nil {
			t.Fatal("unattested flow protocol/domain received a router path", err)
		}
	}
	if got, err := read(0, input, BGPRoutingBudget{MemoryBytes: 1, WorkUnits: 1}); !errors.Is(err, ErrBGPRoutingBudget) || got.Source.Route.Paths != nil {
		t.Fatal("unadmitted flow lookup exposed partial routing evidence", err)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='flow_exporter'`, f.tenants[0], "routing-flow")
		return err
	})
	if got, err := read(0, input, routingViewBudget()); !errors.Is(err, ErrBGPRoutingFlowSource) || got.Owner.RouterID != "" {
		t.Fatal("removed flow owner retained access to router evidence", err)
	}
	check(1)
	routingFlowFixtureAssignment(t, f, f.tenants[0], "routing-flow", "192.0.2.1")
	if got, err := read(0, input, routingViewBudget()); !errors.Is(err, ErrBGPRoutingFlowSource) || got.Source.Route.Paths != nil {
		t.Fatal("recreated flow binding reused pre-assignment sender evidence", err)
	}
	routingFlowFixtureEvidence(t, f, f.tenants[0], "routing-flow", serials[0], "192.0.2.1")
	check(0)
	// An unobserved competing assignment still makes ownership ambiguous.
	routingFlowFixtureAssignment(t, f, f.tenants[0], "routing-flow-unobserved", input.Exporter.String())
	if got, err := read(0, input, routingViewBudget()); !errors.Is(err, ErrBGPRoutingFlowSource) || got.Source.Route.Paths != nil {
		t.Fatal("unobserved competing exporter manufactured unique routing ownership", err)
	}
	check(1)
}

func routingFlowFixtureAssignment(t *testing.T, f *roleInputsFixture, tenant, agent, exporter string) {
	t.Helper()
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, tenant, agent, f.contextID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'flow_exporter',$3,$4,$5)`, tenant, agent, exporter, f.contextID, f.routerID)
		return err
	})
}

func routingFlowFixtureEvidence(t *testing.T, f *roleInputsFixture, tenant, agent, serial, exporter string) {
	t.Helper()
	claim := entity.Observation{ID: uuid.NewString(), Source: entity.SourceKey{AgentID: agent, Kind: entity.FlowExporter, SourceRef: exporter}, Alias: entity.AliasKey{Kind: entity.FlowExporterAlias, Value: exporter + "/ipfix/4294967295"}, SourceRef: "flow:ipfix:domain:4294967295", ObservedAt: f.observedAt(tenant)}
	accepted, unresolved, err := NewEntityRegistry(f.pool).WriteEvidenceBatch(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), agent, serial, []entity.Observation{claim})
	if err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("current explicit flow evidence was not accepted", accepted, unresolved, err)
	}
}

func newRoutingFlowCaptureFixture(t *testing.T) (*roleInputsFixture, []BGPRoutingChange, []string, BGPRoutingFlowInput) {
	t.Helper()
	f := newRoleInputsFixture(t)
	const exporter, agent = "192.0.2.1", "routing-flow"
	sources := []BGPRoutingSource{routingFixtureSource(f, 0), routingFixtureSource(f, 1)}
	changes := make([]BGPRoutingChange, len(sources))
	serials := make([]string, len(sources))
	for lane, source := range sources {
		ref := routingLookupBegin(t, f, source, routingLookupDefinition(1))
		change := routingChangeFixture()
		change.Prefix = netip.MustParsePrefix("203.0.113.0/24")
		change.Segments[1].Values[0] = uint32(64496 + lane)
		changes[lane] = change
		routingLookupApply(t, f, source, ref, BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, Changes: []BGPRoutingChange{change}})
		routingLookupApply(t, f, source, ref, BGPRoutingBatch{Sequence: 2, AFI: 1, SAFI: 1, EndOfRIB: true})
		serials[lane] = strings.ReplaceAll(uuid.NewString(), "-", "")
		if err := NewAgentIdentities(f.pool).Record(t.Context(), source.TenantID, agent, crypto.EntitySPIFFEID(source.TenantID, agent), serials[lane], time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		routingFlowFixtureAssignment(t, f, source.TenantID, agent, exporter)
		routingFlowFixtureEvidence(t, f, source.TenantID, agent, serials[lane], exporter)
		f.peerAtAddress(source.TenantID, "2001:db8::1", uint32(65010+lane))
	}
	input := BGPRoutingFlowInput{Exporter: netip.MustParseAddr(exporter), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("203.0.113.2"), Protocol: "ipfix", Domain: ^uint32(0)}
	return f, changes, serials, input
}
