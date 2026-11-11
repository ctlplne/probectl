// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// Actual pinned FRR, shipped collector/control processes, issued source and
// evidence mTLS, public operator configuration and app-role TLS Postgres/RLS.
// This is the selected-RIB source/storage proof; flow join, public fallback,
// estimate, every served field and multi-VRF physical proof remain separate.
func TestFRRSelectedRIBReachesCurrentTenantStoreThroughAuthenticatedCollectors(t *testing.T) {
	proveFRRSelectedRIB(t, false)
}

func TestFRRSelectedRIBJoinsShippedProtocolGoldenFields(t *testing.T) {
	proveFRRSelectedRIB(t, true)
}

func proveFRRSelectedRIB(t *testing.T, goldenFlows bool) {
	t.Helper()
	if runtime.GOOS != "linux" {
		testsupport.SkipOrFatal(t, "selected-RIB integration needs a Linux route to the owned FRR bridge")
	}
	lab := startRoutingLabNamed(t, "probectl-qa-beta-selected-rib-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	link := addRoleRouterLink(t, lab, "transit", "edge", 234, edgeASN, entity.InterfaceRoleTransit)
	// The additional link supplies native IPv6 transport only; retain the
	// original source's exact IPv4 export policy on the original session.
	lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(rtrAASN), "-c", "no neighbor "+link.peerIP, "-c", "end")
	lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(edgeASN), "-c", "no neighbor "+link.routerIP, "-c", "end")
	const external6 = "2001:db8:5000::/48"
	lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal", "-c", "route-map FX5-V6-ORIGIN permit 10", "-c", "set as-path prepend "+strconv.Itoa(originA), "-c", "exit", "-c", "router bgp "+strconv.Itoa(edgeASN), "-c", "address-family ipv6 unicast", "-c", "network "+external6+" route-map FX5-V6-ORIGIN", "-c", "end")
	lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(rtrAASN), "-c", "address-family ipv6 unicast", "-c", "no network "+link.prefix6, "-c", "exit-address-family", "-c", "bmp targets probectl", "-c", "bmp monitor ipv4 unicast loc-rib", "-c", "bmp monitor ipv6 unicast loc-rib", "-c", "bmp stats interval 1000", "-c", "end")
	// Check the router again after all source configuration, independently of
	// its BMP serializer. A serialized outbound path must never replace the
	// selected path merely to satisfy a stored-state assertion.
	lab.awaitRoutes(t, "rtr-a", map[string]string{prefixA: path(edgeASN, originA)})
	logFRRSelectedRouterTables(t, lab)
	st := shipped.Start(t, shipped.Options{Name: "selected-rib", TenantBand: 4})
	first := registerEdgeFlowEvidence(t, st, lab.ip["rtr-a"])
	second := registerSecondRouterTenant(t, st, first)
	listeners := []*bgpTenant{
		startRouterBMPEvidenceListenerNamed(t, st, lab, first, first.deviceID, "fx5-first"),
		startRouterBMPEvidenceListenerNamed(t, st, lab, second, second.deviceID, "fx5-second"),
	}
	registrations := []edgeFlowRegistration{first, second}
	pool := st.ApplicationReadPool(t)
	t.Cleanup(func() {
		if t.Failed() {
			logFRRSelectedRouterTables(t, lab)
			for _, reg := range registrations {
				logFRRRoutingState(t, pool, reg)
			}
		}
	})
	manifests := make([]store.BGPRoutingBindingConfiguration, 2)
	before := make([]store.BGPRoutingLookup, 2)
	for lane, reg := range registrations {
		manifests[lane] = putFRRSelectedRIBBinding(t, st, reg, listeners[lane], lab.ip["rtr-a"], "", true)
		listeners[lane].reconnectBMP()
	}
	for lane, reg := range registrations {
		before[lane] = awaitFRRSelectedPath(t, pool, reg, "203.0.113.1", prefixA, []uint32{edgeASN, originA}, netip.MustParseAddr(lab.ip["edge"]))
		v6 := awaitFRRSelectedPath(t, pool, reg, "2001:db8:5000::1", external6, []uint32{edgeASN, originA}, netip.MustParseAddr(link.peerIP6))
		awaitFRRSelectedPath(t, pool, reg, netip.MustParsePrefix(link.prefix6).Addr().Next().String(), link.prefix6, []uint32{edgeASN}, netip.MustParseAddr(link.peerIP6))
		// The owned source configuration has exactly one IPv4 selected prefix
		// and two IPv6 prefixes; every prefix/path is checked above.
		for _, expected := range []struct {
			view  store.BGPRoutingLookup
			count int
		}{{before[lane], 1}, {v6, 2}} {
			var rows int
			if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(reg.tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_entries WHERE tenant_id=$1 AND context_id=$2 AND view_id=$3 AND generation=$4`, reg.tenantID, reg.contextID, expected.view.View.ID, expected.view.View.Generation).Scan(&rows)
			}); err != nil || rows != expected.count {
				t.Fatal("complete owned FRR source prefix/path set was truncated or mixed", rows, expected.count, err)
			}
		}
	}
	if before[0].Source.TenantID != first.tenantID || before[1].Source.TenantID != second.tenantID || before[0].View.Generation == before[1].View.Generation {
		t.Fatal("actual source current RIB crossed its paired tenant generation")
	}
	if _, err := readFRRSelectedPath(t.Context(), pool, first.tenantID, second, "203.0.113.1"); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatal("foreign canonical router bypassed tenant-first read", err)
	}
	var foreign int
	if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(first.tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1`, second.tenantID).Scan(&foreign)
	}); err != nil || foreign != 0 {
		t.Fatal("actual app-role RIB storage crossed tenant RLS", foreign, err)
	}
	if goldenFlows {
		proveFRRSelectedGoldenFlowFields(t, st, lab, first, second)
		return
	}
	// Observe genuine source-driven liveness after both complete initial dumps;
	// no local timer, socket state or fabricated frame may renew the current RIB.
	for lane, reg := range registrations {
		baseline := before[lane]
		shipped.Await(t, "actual FRR Loc-RIB statistics to advance its source clock", 5*time.Second, func() bool {
			current, err := readFRRSelectedPath(t.Context(), pool, reg.tenantID, reg, "203.0.113.1")
			return err == nil && current.View.Generation == baseline.View.Generation && current.LastSequence > baseline.LastSequence && current.LastObservedAt.After(baseline.LastObservedAt)
		})
	}
	// Withdraw the operator delegation while both authenticated source sockets
	// stay alive. It cannot refresh the old generation or affect the sibling.
	manifests[0] = putFRRSelectedRIBBinding(t, st, first, listeners[0], lab.ip["rtr-a"], manifests[0].Manifest.Epoch, false)
	if got, err := readFRRSelectedPath(t.Context(), pool, first.tenantID, first, "203.0.113.1"); !errors.Is(err, store.ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
		t.Fatal("withdrawn source binding retained current RIB authority", err)
	}
	awaitFRRSelectedPath(t, pool, second, "203.0.113.1", prefixA, []uint32{edgeASN, originA}, netip.MustParseAddr(lab.ip["edge"]))
	manifests[0] = putFRRSelectedRIBBinding(t, st, first, listeners[0], lab.ip["rtr-a"], manifests[0].Manifest.Epoch, true)
	listeners[0].reconnectBMP()
	restored := awaitFRRSelectedPath(t, pool, first, "203.0.113.1", prefixA, []uint32{edgeASN, originA}, netip.MustParseAddr(lab.ip["edge"]))
	if restored.View.Generation == before[0].View.Generation {
		t.Fatal("restored real source revived an old generation instead of a fresh complete dump")
	}
	// Change the source itself, rather than directly deleting or replacing a
	// stored route. Both tenant streams must withdraw only the affected prefix.
	lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(edgeASN), "-c", "address-family ipv4 unicast", "-c", "no network "+prefixA+" route-map ORIGIN-A", "-c", "end")
	for _, reg := range registrations {
		shipped.Await(t, "real FRR withdrawal to remove its selected prefix", 30*time.Second, func() bool {
			got, err := readFRRSelectedPath(t.Context(), pool, reg.tenantID, reg, "203.0.113.1")
			return errors.Is(err, store.ErrBGPRoutingRouteMissing) && got.Paths == nil
		})
		awaitFRRSelectedPath(t, pool, reg, "2001:db8:5000::1", external6, []uint32{edgeASN, originA}, netip.MustParseAddr(link.peerIP6))
	}
	t.Log("real-integration: actual FRR dual-family Loc-RIB, public configuration, issued collector/origin mTLS, app-role TLS/RLS, source liveness/delegation/restart/withdrawal; no flow/forwarding or multi-VRF hardware claim")
}

func logFRRSelectedRouterTables(t *testing.T, lab *routingLab) {
	t.Helper()
	for _, family := range []string{"ipv4", "ipv6"} {
		// This isolated fixture contains only the hand-specified test prefixes;
		// no running configuration, credentials or operator routes are logged.
		t.Logf("selected-RIB router %s table: %s", family, lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "show bgp "+family+" unicast json"))
	}
}

func putFRRSelectedRIBBinding(t *testing.T, st *shipped.Stack, reg edgeFlowRegistration, listener *bgpTenant, identifier, epoch string, enabled bool) store.BGPRoutingBindingConfiguration {
	t.Helper()
	bindings := []store.BGPRoutingBinding{}
	if enabled {
		bindings = append(bindings, store.BGPRoutingBinding{ContextID: reg.contextID, RouterID: reg.deviceID, Distinguisher: "0000000000000000", BGPIdentifier: identifier, Families: []uint16{1, 2}, SourceFormat: store.BGPRoutingSourceFRRLocRIBV1})
	}
	code, body := st.Do(t, reg.cookie, http.MethodPut, "/v1/entity-contexts/"+reg.contextID+"/bgp-routing-bindings", map[string]any{"collector_agent_id": listener.collectorID, "source_ref": listener.routerID, "expected_epoch": epoch, "bindings": bindings})
	var got store.BGPRoutingBindingConfiguration
	if code != http.StatusOK || json.Unmarshal(body, &got) != nil || got.Manifest == nil || len(got.Manifest.Bindings) != len(bindings) {
		t.Fatalf("public real-source complete binding failed: HTTP%d", code)
	}
	return got
}

func readFRRSelectedPath(ctx context.Context, pool *pgxpool.Pool, tenant string, reg edgeFlowRegistration, address string) (store.BGPRoutingLookup, error) {
	var got store.BGPRoutingLookup
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		got, err = (store.BGPRouting{}).LookupRouterInScope(ctx, sc, entity.Scope{TenantID: reg.tenantID, ContextID: reg.contextID}, reg.deviceID, netip.MustParseAddr(address), store.BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, StateBytes: 1 << 30, LeaseDuration: time.Minute})
		return err
	})
	return got, err
}

func awaitFRRSelectedPath(t *testing.T, pool *pgxpool.Pool, reg edgeFlowRegistration, address, prefix string, expected []uint32, nextHop netip.Addr) store.BGPRoutingLookup {
	t.Helper()
	var got store.BGPRoutingLookup
	last := "no current lookup completed"
	defer func() {
		if t.Failed() {
			t.Logf("selected-RIB lookup for %s: %s", prefix, last)
		}
	}()
	shipped.Await(t, "actual FRR complete selected prefix "+prefix, 30*time.Second, func() bool {
		current, err := readFRRSelectedPath(t.Context(), pool, reg.tenantID, reg, address)
		last = fmt.Sprintf("error=%v prefix=%s paths=%+v generation=%s sequence=%d observed=%s", err, current.Prefix, current.Paths, current.View.Generation, current.LastSequence, current.LastObservedAt)
		if err != nil || current.Prefix.String() != prefix || len(current.Paths) != 1 {
			return false
		}
		path := []uint32{}
		for _, segment := range current.Paths[0].Segments {
			if segment.Kind != 2 {
				return false
			}
			path = append(path, segment.Values...)
		}
		if !slices.Equal(path, expected) || !slices.Contains(current.Paths[0].NextHops, nextHop) {
			return false
		}
		got = current
		return true
	})
	return got
}

// On failure expose only this fixture's tenant-scoped routing state. A staged
// dump, a decoder refusal, incomplete EOR and a mismatched selected path need
// different repairs; none is permission to extend the wait or weaken the path.
func logFRRRoutingState(t *testing.T, pool *pgxpool.Pool, reg edgeFlowRegistration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(reg.tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT v.id::text,v.generation::text,v.afi,v.state,v.completed_at IS NOT NULL,v.last_sequence,
 COALESCE(v.message_clock_sequence,0),v.valid_until,v.peer_identity->>'SourceFormat',
 (SELECT count(*) FROM bgp_routing_entries e WHERE e.tenant_id=v.tenant_id AND e.context_id=v.context_id AND e.view_id=v.id AND e.generation=v.generation)
 FROM bgp_routing_views v WHERE v.tenant_id=$1 AND v.context_id=$2 AND v.router_id=$3 ORDER BY v.observed_at,v.afi`, reg.tenantID, reg.contextID, reg.deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			values, err := rows.Values()
			if err != nil {
				return err
			}
			t.Logf("selected-RIB fixture tenant %s view: %v", reg.tenantID, values)
			count++
		}
		t.Logf("selected-RIB fixture tenant %s retained %d views", reg.tenantID, count)
		return rows.Err()
	})
	if err != nil {
		t.Logf("selected-RIB fixture state unavailable: %v", err)
	}
}
