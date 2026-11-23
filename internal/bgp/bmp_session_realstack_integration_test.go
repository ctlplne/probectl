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
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type frrBMPSessionPage struct {
	Source store.BMPSessionSource         `json:"source"`
	Items  []store.BMPSessionHistoryPoint `json:"items"`
	Next   string                         `json:"next_cursor"`
}

func frrBMPSessionPath(reg edgeFlowRegistration, listener *bgpTenant, peer string) string {
	query := url.Values{"context_id": {reg.contextID}, "collector_agent_id": {listener.collectorID},
		"source_ref": {listener.routerID}, "peer": {peer}}
	return "/v1/bgp/sessions/" + reg.deviceID + "?" + query.Encode()
}

// Tests actual FRR Peer Up, Peer Down, recovery, churn and session-loss
// correlation using two independent issued BMP and listener credentials.
func TestFRRBMPSessionHistoryKeepsTransitionsAndTenantSignals(t *testing.T) {
	lab := startRoutingLabNamed(t, "probectl-qa-beta-bmp-history-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(rtrAASN),
		"-c", "bmp targets probectl", "-c", "bmp stats interval 1000", "-c", "end")
	lab.awaitRoutes(t, "rtr-a", map[string]string{prefixA: path(edgeASN, originA)})
	st := shipped.Start(t, shipped.Options{Name: "bmp-session-history", TenantBand: 4})
	first := registerEdgeFlowEvidence(t, st, lab.ip["rtr-a"])
	second := registerSecondRouterTenant(t, st, first)
	regs := []edgeFlowRegistration{first, second}
	listeners := []*bgpTenant{
		startRouterBMPEvidenceListenerNamed(t, st, lab, first, first.deviceID, "bmp-history-first"),
		startRouterBMPEvidenceListenerNamed(t, st, lab, second, second.deviceID, "bmp-history-second"),
	}
	peer := lab.ip["edge"]
	var connections [2]string
	var retained [2]frrBMPSessionPage
	var status [2]int
	var wanted []string
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for lane, page := range retained {
			t.Logf("BMP lane %d: HTTP %d, selected connection %s, %d points, more=%t, wanted %v",
				lane, status[lane], connections[lane], len(page.Items), page.Next != "", wanted)
			for _, item := range page.Items {
				if item.Neighbor == nil || item.Neighbor.Peer.PeerAddress.String() != peer {
					continue
				}
				t.Logf("BMP lane %d: connection %s sequence %d view %s state %s gap=%t",
					lane, item.Connection, item.Sequence, item.Neighbor.Peer.View, item.Neighbor.State, item.CoverageGap)
			}
		}
	})
	read := func(lane int) bool {
		code, body := st.Do(t, regs[lane].cookie, http.MethodGet, frrBMPSessionPath(regs[lane], listeners[lane], peer), nil)
		status[lane] = code
		if code != http.StatusOK {
			return false
		}
		// Decode each poll into a fresh page. Reusing the slice would let
		// omitted fields on a new row inherit evidence from an earlier poll.
		var page frrBMPSessionPage
		if json.Unmarshal(body, &page) != nil || page.Source.RouterID != regs[lane].deviceID || page.Source.ContextID != regs[lane].contextID {
			t.Fatal("served BMP history lost its exact authorized tuple")
		}
		for _, item := range page.Items {
			if (item.Kind == "neighbor") != (item.Neighbor != nil) {
				t.Fatal("served BMP row has mismatched neighbor evidence", item.Kind, item.Sequence)
			}
		}
		retained[lane] = page
		return true
	}
	awaitNeighbors := func(expected []string) {
		t.Helper()
		wanted = expected
		for lane := range regs {
			shipped.Await(t, fmt.Sprintf("BMP lane %d to retain transitions %v on the issued router connection", lane, expected), 25*time.Second, func() bool {
				if !read(lane) {
					return false
				}
				var newest []string
				for _, item := range retained[lane].Items {
					if item.Neighbor == nil || item.Neighbor.Peer.PeerAddress.String() != peer {
						continue
					}
					if connections[lane] == "" {
						connections[lane] = item.Connection
					}
					if item.Connection != connections[lane] {
						continue
					}
					neighbor := item.Neighbor
					if item.CoverageGap || neighbor.FrameDigest == "" || neighbor.State == "down" && (neighbor.DownReason == nil || *neighbor.DownReason == 5) {
						t.Fatal("original FRR reason, connection or coverage is invalid")
					}
					if len(newest) == 0 || newest[len(newest)-1] != neighbor.State {
						newest = append(newest, neighbor.State)
					}
				}
				slices.Reverse(newest)
				return slices.Equal(newest, expected)
			})
		}
	}
	awaitNeighbors([]string{"up"})
	for step, shutdown := range []bool{true, false, true, false} {
		command := "no neighbor " + peer + " shutdown"
		if shutdown {
			command = "neighbor " + peer + " shutdown"
		}
		lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(rtrAASN), "-c", command, "-c", "end")
		// Wait for the running router to report the transition before moving on.
		// Show output is a second independent view of the peer's state.
		shipped.Await(t, "actual FRR BGP session summary", 20*time.Second, func() bool {
			raw := lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "show bgp ipv4 unicast summary json")
			return roleRouterSessionEstablished([]byte(raw), peer) != shutdown
		})
		// Waiting for the BMP record on both lanes prevents a short fixture flap
		// from racing the mTLS intake and hiding a real router transition.
		awaitNeighbors([]string{"up", "down", "up", "down", "up"}[:step+2])
	}
	awaitNeighbors([]string{"up", "down", "up", "down", "up"})
	if connections[0] == connections[1] || connections[0] == "" || connections[1] == "" {
		t.Fatal("two issued tenant lanes shared a BMP connection identity")
	}
	pool := st.ApplicationReadPool(t)
	for lane, reg := range regs {
		shipped.Await(t, "actual FRR neighbor statistics and observed UPDATE frames", 15*time.Second, func() bool {
			if !read(lane) {
				return false
			}
			var count, updates bool
			for _, item := range retained[lane].Items {
				if item.Statistics != nil {
					for _, sample := range item.Statistics.Samples {
						count = count || !sample.Counter && sample.Value > 0
					}
				}
				updates = updates || item.UpdateChurn != nil && item.UpdateChurn.Updates > 0
			}
			return count && updates
		})
		var losses, flaps, incidents int
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(reg.tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE kind='bgp.session_loss'),count(*) FILTER (WHERE kind='bgp.session_flap'),
 count(DISTINCT incident_id) FROM incident_signals WHERE kind IN ('bgp.session_loss','bgp.session_flap')
 AND attributes->>'probectl.bgp.bmp.connection_id'=$1`, connections[lane]).Scan(&losses, &flaps, &incidents)
		})
		if err != nil || losses != 2 || flaps != 1 || incidents != 1 {
			t.Fatal("actual peer loss and flap did not correlate within the tenant", losses, flaps, incidents, err)
		}
		code, _ := st.Do(t, reg.cookie, http.MethodGet, frrBMPSessionPath(regs[1-lane], listeners[1-lane], peer), nil)
		if code != http.StatusNotFound {
			t.Fatal("one tenant selected the sibling router or listener", code)
		}
	}
	t.Log("real-integration: original pinned FRR transitions, distinct issued mTLS source connections, RIB gauges, observed UPDATE windows, and exact two-loss/one-flap scoped incidents")
}
