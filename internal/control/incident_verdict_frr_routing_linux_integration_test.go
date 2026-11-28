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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
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
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func startVerdictInternetFRR(t *testing.T, healthy bool) verdictInternetLab {
	t.Helper()
	path := startVerdictFRRPath(t, true)
	network, external := path.network, path.external
	enableVerdictExternalForwarding(t, network, external)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, namespace := range []string{external, network.source, network.other} {
			routes, routeErr := exec.CommandContext(ctx, "ip", "-n", namespace, "-4", "route", "show").CombinedOutput()
			counters, counterErr := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "cat", "/proc/net/snmp").CombinedOutput()
			t.Logf("namespace %s IPv4 routes (%v): %s\nprotocol counters (%v): %s", namespace, routeErr, routes, counterErr, counters)
		}
	})
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
			path.awaitEstablished(t)
			path.awaitExternalRoute(t)
			configureVerdictFRRBinding(t, f, tenant)
			conn := openVerdictFRRBMP(t, network.router)
			peer, route := captureVerdictExternalRoute(t, conn, f, tenant, listener)
			if !healthy {
				// Withdraw the test destinations and finish their FIB lookup
				// with no route. The advertised responder prefix stays up.
				for _, definition := range definitions {
					prefix := definition.Target + "/32"
					dependencyLabCommand(t, "ip", "-n", external, "addr", "del", prefix, "dev", "lo")
					dependencyLabCommand(t, "ip", "-n", external, "route", "replace", "throw", prefix)
				}
			}
			return peer, route
		},
	}
}

func (lab verdictFRRPath) awaitExternalRoute(t *testing.T) {
	t.Helper()
	shipped.Await(t, "stock FRR established the external BGP origin session", 25*time.Second, func() bool {
		return lab.carrier.neighborState(t, verdictFRRExternalIP) == "Established"
	})
	wantPath := fmt.Sprintf("%d %d", verdictFRRCarrierASN, verdictFRRExternalASN)
	// Check convergence before opening BMP so that the selected responder
	// route is in the initial dump. Only that dump supplies the proof.
	shipped.Await(t, "stock FRR selected "+verdictFRRExternalPrefix+" via "+wantPath, 25*time.Second, func() bool {
		raw := verdictFRRDocker(t, "exec", lab.local.id, "vtysh", "-c", "show bgp ipv4 unicast json")
		var table struct {
			Routes map[string][]struct {
				Path     string `json:"path"`
				BestPath bool   `json:"bestpath"`
			} `json:"routes"`
		}
		if err := json.Unmarshal([]byte(raw), &table); err != nil {
			t.Fatal("could not read the stock router's IPv4 BGP table", err)
		}
		for _, route := range table.Routes[verdictFRRExternalPrefix] {
			if route.BestPath && route.Path == wantPath {
				return true
			}
		}
		return false
	})
}

func enableVerdictExternalForwarding(t *testing.T, network dependencyPhysicalNetwork, external string) {
	t.Helper()
	dependencyLabCommand(t, "ip", "netns", "exec", network.child, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	dependencyLabCommand(t, "ip", "netns", "exec", external, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.icmp_ratemask=0")
	// The source namespace has no default route. Give both probes a reverse
	// path to the original ICMP sender, which is separate from their targets.
	dependencyLabCommand(t, "ip", "-n", network.source, "route", "add", verdictFRRExternalIP+"/32", "via", "10.250.0.1")
	for _, prefix := range []string{"10.250.0.0/30", "10.250.2.0/30"} {
		dependencyLabCommand(t, "ip", "-n", external, "route", "add", prefix, "via", verdictFRRExternalPeerIP, "src", verdictFRRExternalIP)
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
	var frames [4][4]int // BMP message type, then BMP peer type
	var lookupErr error
	const origin = "role-router"
	originSerial := f.serials[tenant+origin]
	for peer == nil || selected.ID == "" {
		raw, err := readVerdictFRRFrame(conn)
		if err != nil {
			t.Fatalf("stock FRR dump incomplete: physical_peer=%t selected_view_staged=%t selected_route_current=%t applied_updates=%d frames_by_message_and_peer_type=%v last_lookup=%v: %v",
				peer != nil, staged.ID != "", selected.ID != "", sequence, frames, lookupErr, err)
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
		frames[raw[5]][header.PeerType]++
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
			selected, lookupErr = lookupVerdictExternalRoute(t, f, tenant, staged)
		case 2:
			t.Fatal("stock FRR withdrew the selected view before the verdict")
		}
	}
	return peer, selected
}

func lookupVerdictExternalRoute(t *testing.T, f *roleExplanationAPIFixture, tenant string, staged store.BGPRoutingViewRef) (store.BGPRoutingViewRef, error) {
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
		return store.BGPRoutingViewRef{}, err
	}
	if err != nil || got.Source.TenantID != tenant || got.View != staged || got.Prefix.String() != verdictFRRExternalPrefix ||
		len(got.Paths) != 1 || len(got.Paths[0].Segments) != 1 ||
		!slices.Equal(got.Paths[0].Segments[0].Values, []uint32{verdictFRRCarrierASN, verdictFRRExternalASN}) {
		t.Fatal("the stored selected responder route lost its tenant, original generation or distinct carrier and origin ASNs", err)
	}
	return got.View, nil
}
