// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package change

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOwnedRouteReferenceKeepsOriginalSequenceAndSelectedViewMeaning(t *testing.T) {
	for _, contextID := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		reference := RouteReference{Version: 1, ContextID: contextID, RouterID: "22222222-2222-4222-8222-222222222222", BaseContextID: contextID,
			BaseRouterID: "22222222-2222-4222-8222-222222222222", ViewID: "33333333-3333-4333-8333-333333333333", Generation: "44444444-4444-4444-8444-444444444444",
			Sequence: "9007199254740993", BatchDigest: strings.Repeat("a", 64), View: "loc_rib", Action: "selected_route_update", AFI: 2, SAFI: 1, HasPathID: true, PathID: 0, PriorPresent: true, PathChanged: true}
		reference.ObservedAt = time.Unix(1794664800, 123456789).UTC()
		if err := reference.Validate(); err != nil {
			t.Fatal("original selected route reference refused", err)
		}
		raw, err := json.Marshal(reference)
		if err != nil || !strings.Contains(string(raw), `"sequence":"9007199254740993"`) {
			t.Fatal("original sequence rounded", err)
		}
		var decoded RouteReference
		if json.Unmarshal(raw, &decoded) != nil || decoded != reference {
			t.Fatal("route reference changed original metadata")
		}
		for _, mutate := range []func(*RouteReference){
			func(r *RouteReference) { r.View = "adj_rib_in_post_policy" },
			func(r *RouteReference) { r.PriorPresent = false },
			func(r *RouteReference) { r.PathChanged = false; r.AttributesChanged = false },
			func(r *RouteReference) { r.Sequence = "09007199254740993" },
			func(r *RouteReference) { r.UpdateIndex = -1 },
			func(r *RouteReference) { r.BatchDigest = strings.Repeat("A", 64) },
			func(r *RouteReference) { r.RouterID = "alias-router" },
			func(r *RouteReference) { r.HasPathID = false; r.PathID = 1 },
		} {
			invalid := reference
			mutate(&invalid)
			if invalid.Validate() == nil {
				t.Fatal("invalid metadata invented selected-route meaning", invalid)
			}
		}
	}
}

func TestOwnedRouteCorrelationRequiresExactCanonicalRouterAndContext(t *testing.T) {
	at := time.Now().UTC()
	const contextID = "11111111-1111-4111-8111-111111111111"
	const routerID = "22222222-2222-4222-8222-222222222222"
	reference := RouteReference{Version: 1, ContextID: contextID, RouterID: routerID, BaseContextID: contextID, BaseRouterID: routerID, ViewID: "33333333-3333-4333-8333-333333333333", Generation: "44444444-4444-4444-8444-444444444444", Sequence: "1", BatchDigest: strings.Repeat("a", 64), ObservedAt: at, View: "loc_rib", Action: "announcement", AFI: 1, SAFI: 1}
	events := []Event{{ID: "original", Kind: KindRoute, Target: routerID, Prefix: "198.19.0.0/24", OccurredAt: at, Routing: &reference}}
	if got := Candidates(events, routerID, "198.19.0.0/24", at, time.Hour); len(got) != 0 {
		t.Fatal("name/prefix-only correlation acquired owned routing authority")
	}
	for _, identity := range [][2]string{{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", routerID}, {contextID, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}} {
		if got := CandidatesForIdentity(events, routerID, "198.19.0.0/24", identity[0], identity[1], at, time.Hour); len(got) != 0 {
			t.Fatal("shared router name or prefix crossed canonical context")
		}
	}
	got := CandidatesForIdentity(events, routerID, "198.19.0.0/24", contextID, routerID, at, time.Hour)
	if len(got) != 1 || got[0].Event.ID != "original" || !strings.Contains(got[0].Reason, "no forwarding-state claim") {
		t.Fatal("canonical router change lost honest observation coverage", got)
	}
}
