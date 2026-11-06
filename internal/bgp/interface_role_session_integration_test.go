// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

func TestInterfaceRoleFamilySummaryRequiresTheExactEstablishedPeer(t *testing.T) {
	for _, tc := range []struct {
		name, raw, peer string
		want            bool
	}{
		{"ipv4", `{"routerId":"192.0.2.1","peers":{"10.234.1.12":{"state":"Established"},"10.234.1.13":{"state":"Active"}}}`, "10.234.1.12", true},
		{"ipv6", `{"routerId":"192.0.2.1","peers":{"fd42:ea:1::12":{"state":"Established"}}}`, "fd42:ea:1::12", true},
		{"other-peer", `{"peers":{"10.234.1.12":{"state":"Established"}}}`, "10.234.1.13", false},
		{"active", `{"peers":{"10.234.1.12":{"state":"Active"}}}`, "10.234.1.12", false},
		{"missing-state", `{"peers":{"10.234.1.12":{}}}`, "10.234.1.12", false},
		{"wildcard-shape", `{"ipv4Unicast":{"peers":{"10.234.1.12":{"state":"Established"}}}}`, "10.234.1.12", false},
		{"malformed", `{"peers":`, "10.234.1.12", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if roleRouterSessionEstablished([]byte(tc.raw), tc.peer) != tc.want {
				t.Fatal("family summary lost exact peer session state")
			}
		})
	}
}

// This narrow native proof also runs on Docker Desktop: it never needs a Mac
// route to the private Linux bridge, Postgres, or the shipped UI stack.
func TestInterfaceRoleFRRRelationshipSessionsKeepBothFamilies(t *testing.T) {
	lab := startRoutingLabNamed(t, "probectl-qa-beta-role-links-"+strconv.FormatInt(time.Now().UnixNano()%1e8, 36))
	link := addRoleRouterLink(t, lab, "transit", "edge", 234, edgeASN, entity.InterfaceRoleTransit)
	for _, family := range []string{"ipv4", "ipv6"} {
		peer := link.peerIP
		if family == "ipv6" {
			peer = link.peerIP6
		}
		raw := lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "show bgp "+family+" unicast summary json")
		if !roleRouterSessionEstablished([]byte(raw), peer) {
			t.Fatalf("real family summary lost established %s peer: %s", family, raw)
		}
		var summary map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &summary) != nil || len(summary["peers"]) == 0 {
			t.Fatal("pinned FRR family summary did not contain root peers")
		}
		t.Logf("real-integration: pinned FRR %s family summary: %s", family, raw)
		lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(rtrAASN), "-c", "neighbor "+peer+" shutdown", "-c", "end")
		deadline := time.Now().Add(5 * time.Second)
		for {
			raw, err := exec.Command("docker", "exec", lab.container("rtr-a"), "vtysh", "-c", "show bgp "+family+" unicast summary json").Output()
			var stopped struct {
				Peers map[string]struct {
					State string `json:"state"`
				} `json:"peers"`
			}
			if err == nil && json.Unmarshal(raw, &stopped) == nil && stopped.Peers[peer].State != "" &&
				!roleRouterSessionEstablished(raw, peer) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("shutdown peer retained an established session")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
