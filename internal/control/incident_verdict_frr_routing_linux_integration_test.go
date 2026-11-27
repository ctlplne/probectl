// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

func startVerdictInternetFRR(t *testing.T, healthy bool) verdictInternetLab {
	t.Helper()
	path := startVerdictFRRPath(t, true)
	network, external := path.network, path.external
	enableVerdictExternalForwarding(t, network, external)
	vantages := [2]string{network.source, network.other}
	return verdictInternetLab{
		verdictHandoffLab: verdictHandoffLab{
			peerASN: verdictFRRCarrierASN,
			states:  func() [2]entity.SNMPInterfaceState { return verdictFRRLinkStates(t, network) },
			probes: func(t *testing.T, healthy bool, senders []string, definitions []testspec.ExecutableDefinition) [2]entity.Observation {
				result := collectVerdictInternetProbes(t, vantages, healthy, senders, definitions)
				path.local.requireEstablished(t, verdictFRRCarrierIP)
				path.carrier.requireEstablished(t, verdictFRRExternalIP)
				return result
			},
		},
		capture: func(f *roleExplanationAPIFixture, tenant string, listener *agent.EvidenceClient, definitions []testspec.ExecutableDefinition) (*entity.BMPPeerSession, store.BGPRoutingViewRef) {
			routeVerdictICMPTargets(t, network, external, definitions)
			for _, definition := range definitions {
				dependencyLabCommand(t, "ip", "-n", network.child, "route", "add", definition.Target+"/32", "via", verdictFRRExternalIP)
			}
			checkVerdictICMPBaseline(t, vantages, definitions)
			configureVerdictFRRBinding(t, f, tenant)
			conn := openVerdictFRRBMP(t, network.router)
			peer, route := captureVerdictExternalRoute(t, conn, f, tenant, listener)
			if !healthy {
				// Withdraw only the test destinations on the far router.
				// Its advertised responder prefix and both sessions stay up.
				for _, definition := range definitions {
					dependencyLabCommand(t, "ip", "-n", external, "addr", "del", definition.Target+"/32", "dev", "lo")
				}
			}
			return peer, route
		},
	}
}

func enableVerdictExternalForwarding(t *testing.T, network dependencyPhysicalNetwork, external string) {
	t.Helper()
	dependencyLabCommand(t, "ip", "netns", "exec", network.child, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	dependencyLabCommand(t, "ip", "netns", "exec", external, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.icmp_ratelimit=0")
	for _, prefix := range []string{"10.250.0.0/30", "10.250.2.0/30"} {
		dependencyLabCommand(t, "ip", "-n", external, "route", "add", prefix, "via", verdictFRRExternalPeerIP)
	}
}

func configureVerdictFRRBinding(t *testing.T, f *roleExplanationAPIFixture, tenant string) {
	t.Helper()
	epoch := ""
	bindings := []store.BGPRoutingBinding{{
		ContextID: f.contextID, RouterID: f.routerID, Distinguisher: "0000000000000000",
		BGPIdentifier: verdictFRRLocalIP, Families: []uint16{1}, SourceFormat: store.BGPRoutingSourceFRRLocRIBV1,
	}}
	body, err := json.Marshal(bgpRoutingBindingsInput{
		CollectorAgentID: "role-listener", SourceRef: "role-router", ExpectedEpoch: &epoch, Bindings: &bindings,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+"/v1/entity-contexts/"+f.contextID+"/bgp-routing-bindings", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
	req.Header.Set("Content-Type", "application/json")
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var got store.BGPRoutingBindingConfiguration
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil || res.StatusCode != http.StatusOK ||
		got.ContextID != f.contextID || got.RouterID != f.routerID || got.Manifest == nil ||
		len(got.Manifest.Bindings) != 1 || got.Manifest.Bindings[0].SourceFormat != store.BGPRoutingSourceFRRLocRIBV1 {
		t.Fatal("the tenant could not select the stock FRR routing view", res.StatusCode, err)
	}
}

func captureVerdictExternalRoute(t *testing.T, conn net.Conn, f *roleExplanationAPIFixture, tenant string, listener *agent.EvidenceClient) (*entity.BMPPeerSession, store.BGPRoutingViewRef) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var peer *entity.BMPPeerSession
	var staged store.BGPRoutingViewRef
	var selected store.BGPRoutingViewRef
	var sequence int64
	const origin = "role-router"
	originSerial := f.serials[tenant+origin]
	for peer == nil || selected.ID == "" {
		raw, err := readVerdictFRRFrame(conn)
		if err != nil {
			t.Fatalf("stock FRR did not provide the physical neighbor and a complete selected responder route: %v", err)
		}
		if raw[5] != 0 && raw[5] != 2 && raw[5] != 3 {
			continue
		}
		if len(raw) < 48 {
			t.Fatal("stock FRR omitted the peer header")
		}
		header, err := bgp.ParseBMPRouteViewHeader(raw[6:48])
		if err != nil {
			t.Fatal("the shipped decoder refused the stock FRR view header", err)
		}
		if header.View != bgp.BMPLocRIB {
			if header.PeerAddress.String() != verdictFRRCarrierIP || header.PeerASN != verdictFRRCarrierASN {
				t.Fatal("the stock physical session belonged to a different carrier")
			}
			switch raw[5] {
			case 3:
				peer, err = bgp.DecodePhysicalPeerSession(t.Context(), raw, bgp.PeerMessageBudget{MemoryBytes: verdictMaxBMPFrame, WorkUnits: verdictMaxBMPFrame})
				if err != nil {
					t.Fatal("the physical FRR session could not be decoded", err)
				}
			case 2:
				if peer != nil {
					t.Fatal("the physical handoff went down while collecting the wider-internet source")
				}
			}
			continue
		}
		observed := time.Now().UnixNano()
		switch raw[5] {
		case 3:
			if staged.ID != "" {
				t.Fatal("stock FRR replaced the selected view before its original route was ready")
			}
			receipt, err := listener.StageRoutingPeer(t.Context(), &agentv1.BmpRoutingPeerUp{
				ObservationId: gouuid.NewString(), ConfiguredRef: origin, OriginSerial: originSerial, ObservedUnixNanos: observed, Message: raw,
			})
			if err != nil || receipt.GetStatus() != "staged" || len(receipt.GetViews()) != 1 || receipt.GetViews()[0].GetAfi() != 1 ||
				receipt.GetViews()[0].GetSafi() != 1 {
				t.Fatal("the authenticated FRR selected view failed to stage", err)
			}
			view := receipt.GetViews()[0]
			staged = store.BGPRoutingViewRef{ID: view.GetId(), Generation: view.GetGeneration()}
		case 0:
			if staged.ID == "" {
				t.Fatal("stock FRR sent a selected route before the associated Peer Up")
			}
			sequence++
			if _, err := listener.SubmitRoutingMessage(t.Context(), &agentv1.BmpRoutingMessage{
				ConfiguredRef: origin, OriginSerial: originSerial, Generation: staged.Generation, Sequence: sequence, ObservedUnixNanos: observed, Message: raw,
			}); err != nil {
				t.Fatal("the authenticated receiver refused the original FRR update sequence", sequence, err)
			}
			selected = lookupVerdictExternalRoute(t, f, tenant, staged)
		case 2:
			t.Fatal("stock FRR withdrew the selected view before the verdict")
		}
	}
	return peer, selected
}

func lookupVerdictExternalRoute(t *testing.T, f *roleExplanationAPIFixture, tenant string, staged store.BGPRoutingViewRef) store.BGPRoutingViewRef {
	t.Helper()
	scope := entity.Scope{TenantID: tenant, ContextID: f.contextID}
	var got store.BGPRoutingLookup
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		got, err = (store.BGPRouting{}).LookupRouterInScope(ctx, sc, scope, f.routerID, netip.MustParseAddr(verdictFRRExternalIP),
			store.BGPRoutingBudget{MemoryBytes: 64 << 20, WorkUnits: 64 << 20, StateBytes: 128 << 20})
		return err
	})
	if errors.Is(err, store.ErrBGPRoutingSourceUnavailable) || errors.Is(err, store.ErrBGPRoutingRouteMissing) {
		return store.BGPRoutingViewRef{}
	}
	if err != nil || got.Source.TenantID != tenant || got.View != staged || got.Prefix.String() != verdictFRRExternalPrefix ||
		len(got.Paths) != 1 || len(got.Paths[0].Segments) != 1 ||
		!slices.Equal(got.Paths[0].Segments[0].Values, []uint32{verdictFRRCarrierASN, verdictFRRExternalASN}) {
		t.Fatal("the stored selected responder route lost its tenant, original generation or distinct carrier and origin ASNs", err)
	}
	return got.View
}
