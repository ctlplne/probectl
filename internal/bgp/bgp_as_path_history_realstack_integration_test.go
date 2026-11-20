// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func addFRRPathHistoryMonitors(t *testing.T, st *shipped.Stack, tenants []edgeFlowRegistration) []store.BGPVisibilityMonitor {
	t.Helper()
	monitors := make([]store.BGPVisibilityMonitor, len(tenants))
	for i, registration := range tenants {
		code, body := st.Do(t, registration.cookie, http.MethodPut, "/v1/bgp/visibility",
			map[string]any{"prefix": prefixA, "minimum_visible_basis_points": 9500})
		if code != http.StatusOK || json.Unmarshal(body, &monitors[i]) != nil || monitors[i].Prefix.String() != prefixA {
			t.Fatalf("could not monitor the exact FRR prefix through the shipped API: HTTP %d", code)
		}
	}
	return monitors
}

type frrASPathHistoryEvent struct {
	store.BGPASPathHistoryRecord
	Previous   json.RawMessage    `json:"previous"`
	Current    json.RawMessage    `json:"current"`
	RouterView string             `json:"router_view"`
	Changes    *bgp.ASPathChanges `json:"changes"`
}

func proveFRRPathHistory(t *testing.T, st *shipped.Stack, lab *routingLab, pool *pgxpool.Pool,
	registrations []edgeFlowRegistration, listeners []*bgpTenant, manifests []store.BGPRoutingBindingConfiguration,
	monitors []store.BGPVisibilityMonitor) {
	t.Helper()
	const intermediate, newOrigin = 64506, 64507
	routerIP := netip.MustParseAddr(lab.ip["edge"])
	waitPath := func(expected []uint32) {
		t.Helper()
		for _, lane := range registrations {
			awaitFRRSelectedPath(t, pool, lane, "203.0.113.1", prefixA, expected, routerIP)
		}
	}
	setPrepend := func(value string) {
		t.Helper()
		lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal",
			"-c", "route-map ORIGIN-A permit 10", "-c", "set as-path prepend "+value, "-c", "end")
		lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "clear bgp "+lab.ip["rtr-a"]+" soft out")
	}
	setPrepend(path(intermediate, originA))
	waitPath([]uint32{edgeASN, intermediate, originA})
	setPrepend(path(intermediate, originA, originA))
	waitPath([]uint32{edgeASN, intermediate, originA, originA})
	setPrepend(path(intermediate, newOrigin, newOrigin))
	waitPath([]uint32{edgeASN, intermediate, newOrigin, newOrigin})
	lab.docker(t, "exec", lab.container("edge"), "vtysh", "-c", "configure terminal", "-c", "router bgp "+strconv.Itoa(edgeASN),
		"-c", "address-family ipv4 unicast", "-c", "no network "+prefixA+" route-map ORIGIN-A", "-c", "end")
	var retained [2][]frrASPathHistoryEvent
	for lane, registration := range registrations {
		path := "/v1/bgp/visibility/" + monitors[lane].ID + "/paths"
		shipped.Await(t, "five original FRR selected paths in own shipped history", 35*time.Second, func() bool {
			code, body := st.Do(t, registration.cookie, http.MethodGet, path+"?source=router_bmp", nil)
			if code != http.StatusOK {
				return false
			}
			var page struct {
				Items []frrASPathHistoryEvent
			}
			if json.Unmarshal(body, &page) != nil {
				t.Fatal("shipped API changed the AS-path history contract")
			}
			for _, event := range page.Items {
				if event.RouterView == "operator_loc_rib" {
					retained[lane] = append(retained[lane], event)
				}
			}
			if len(retained[lane]) >= 5 {
				return true
			}
			retained[lane] = nil
			return false
		})
		rows := retained[lane]
		if len(rows) != 5 || rows[0].Kind != "withdrawal" || rows[1].Kind != "path_change" || rows[2].Kind != "path_change" ||
			rows[3].Kind != "path_change" || rows[4].Kind != "baseline" || rows[1].Changes == nil || rows[2].Changes == nil || rows[3].Changes == nil ||
			!rows[1].Changes.OriginChanged || !rows[2].Changes.LengthChanged || rows[2].Changes.UpstreamChanged || !rows[3].Changes.UpstreamChanged ||
			rows[0].ChangeEventID == "" || rows[1].ChangeEventID == "" || rows[2].ChangeEventID == "" || rows[3].ChangeEventID == "" {
			t.Fatalf("shipped AS path timeline lost its original FRR transitions: %v", rows)
		}
		var predecessor struct {
			Segments []bgp.ASPathSegment
		}
		if err := json.Unmarshal(rows[0].Previous, &predecessor); err != nil || len(predecessor.Segments) != 1 ||
			len(predecessor.Segments[0].Values) != 4 || predecessor.Segments[0].Values[3] != newOrigin {
			t.Fatal("withdrawn path lost the exact original prepended source", err)
		}
		foreign := "/v1/bgp/visibility/" + monitors[1-lane].ID + "/paths"
		if code, _ := st.Do(t, registration.cookie, http.MethodGet, foreign, nil); code != http.StatusNotFound {
			t.Fatalf("foreign monitor reached through the shipped history API: HTTP %d", code)
		}
	}
	if retained[0][0].SourceEpoch == retained[1][0].SourceEpoch {
		t.Fatal("two enrolled router sources acquired one shared private generation")
	}
	first := registrations[0]
	revoked := putFRRSelectedRIBBinding(t, st, first, listeners[0], lab.ip["rtr-a"], manifests[0].Manifest.Epoch, false)
	one := "/v1/bgp/visibility/" + monitors[0].ID + "/paths?source=router_bmp&vantage=" + url.QueryEscape(retained[0][0].Vantage)
	if code, _ := st.Do(t, first.cookie, http.MethodGet, one, nil); code != http.StatusNotFound {
		t.Fatalf("revoked physical source history stayed readable: HTTP %d", code)
	}
	two := "/v1/bgp/visibility/" + monitors[1].ID + "/paths?source=router_bmp&vantage=" + url.QueryEscape(retained[1][0].Vantage)
	if code, _ := st.Do(t, registrations[1].cookie, http.MethodGet, two, nil); code != http.StatusOK {
		t.Fatalf("revoking the first source interrupted the sibling: HTTP %d", code)
	}
	from := time.Now().UTC().Add(-time.Millisecond).Format(time.RFC3339Nano)
	putFRRSelectedRIBBinding(t, st, first, listeners[0], lab.ip["rtr-a"], revoked.Manifest.Epoch, true)
	listeners[0].reconnectBMP()
	shipped.Await(t, "fresh complete FRR baseline after the original withdrawal", 35*time.Second, func() bool {
		path := "/v1/bgp/visibility/" + monitors[0].ID + "/paths?source=router_bmp&from=" + url.QueryEscape(from)
		code, raw := st.Do(t, first.cookie, http.MethodGet, path, nil)
		var page struct {
			Items []frrASPathHistoryEvent
		}
		if code != http.StatusOK || json.Unmarshal(raw, &page) != nil {
			return false
		}
		for _, row := range page.Items {
			if row.RouterView == "operator_loc_rib" && row.Kind == "baseline" && len(row.Current) == 0 && row.SourceEpoch != retained[0][0].SourceEpoch {
				return true
			}
		}
		return false
	})
	t.Log("real-integration: FRR announced, changed upstream, prepended, changed origin and withdrew the documentation prefix. Each issued mTLS source retained its own exact history and complete reseed.")
}
