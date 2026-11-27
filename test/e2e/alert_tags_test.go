// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/flow"
)

// Exercise the actual Alerts console with Dex sessions. The read and clear
// both go through HTTPS to the shipped control plane and its tenant store.
func proveReleaseAlertTagCriteria(t *testing.T, root, certificate string, tenants [2]api, objects [2]tenantObjects, sessions []releaseSession) {
	t.Helper()
	const field = "tag.test_customer" // Created by release-test-tag-metadata.
	paths := [2]string{
		"/v1/alerts/rules/" + objects[0].alertID + "/tag-filter",
		"/v1/alerts/rules/" + objects[1].alertID + "/tag-filter",
	}
	for _, theme := range []string{"light", "dark"} {
		var seeded [2]alert.TagFilterState
		for lane, tenant := range tenants {
			tenant.json(t, http.StatusOK, http.MethodPut, paths[lane], alert.TagFilterInput{
				TargetKind: "test",
				Filter: &flow.QueryFilterGroup{
					Match: "all", Mode: "include",
					Conditions: []flow.QueryPredicate{{Field: field, Op: flow.QueryEqual, Values: []string{objects[lane].mark + "-" + theme}}},
				},
			}, &seeded[lane])
			if state := seeded[lane]; state.RuleID != objects[lane].alertID || !state.HasTagFilter ||
				state.TagFilter == nil || state.TagFilter.OwnerUserID == "" || state.TagFilter.TagIDs[field] == "" {
				t.Fatal("released alert API did not bind the owned tag and user")
			}
		}
		if seeded[0].TagFilter.TagIDs[field] == seeded[1].TagFilter.TagIDs[field] ||
			seeded[0].TagFilter.OwnerUserID == seeded[1].TagFilter.OwnerUserID {
			t.Fatal("the same tag key collapsed tenant identities")
		}
		for lane, tenant := range tenants {
			t.Run(fmt.Sprintf("%d/%s", lane, theme), func(t *testing.T) {
				name := objects[lane].mark + "-alert"
				foreignName := objects[1-lane].mark + "-alert"
				const criteria = "[role=dialog]:has-text('Current test tags:')"
				const confirmation = "[role=alertdialog], [role=dialog]:has-text('Remove this rule')"
				renderReleaseBrowser(t, root, map[string]any{
					"url": tenant.base + "/ui/alerts", "theme": theme,
					"cookies":        []map[string]string{{"name": "probectl_session", "value": sessions[lane].Cookie}},
					"trustCertFiles": []string{certificate}, "timeoutMs": 60_000,
					"expect": []string{name},
					"absent": []string{foreignName, seeded[1-lane].TagFilter.OwnerUserID},
					"steps": []map[string]any{
						{"click": "Test tag criteria for " + name, "expectWithin": criteria, "expect": []string{"Current test tags: " + name}},
						{"click": "Load current criteria", "within": criteria, "expectWithin": criteria,
							"expect": []string{"Saved binding revision", seeded[lane].TagFilter.OwnerUserID}},
						{"click": "Clear tag filter", "within": criteria, "expectWithin": confirmation,
							"expect": []string{"Remove this rule's metadata criteria"}},
						{"click": "Clear criteria", "within": confirmation, "expectWithin": criteria,
							"expect": []string{"Tag filter cleared. The rule uses its ordinary metric selection."}},
					},
				})
				var own alert.TagFilterState
				tenant.json(t, http.StatusOK, http.MethodGet, paths[lane], nil, &own)
				if own.RuleID != objects[lane].alertID || own.HasTagFilter || own.TagFilter != nil {
					t.Fatal("browser did not clear the owned alert filter")
				}
				foreign := 1 - lane
				for _, method := range []string{http.MethodGet, http.MethodDelete} {
					status, _ := tenant.do(t, method, paths[foreign], nil)
					if status != http.StatusNotFound && status != http.StatusForbidden {
						t.Fatalf("sibling alert filter %s returned %d", method, status)
					}
				}
				var sibling alert.TagFilterState
				tenants[foreign].json(t, http.StatusOK, http.MethodGet, paths[foreign], nil, &sibling)
				// The first browser must preserve the sibling's exact binding.
				// The second browser must leave the first browser's cleared state.
				if lane == 0 && (!sibling.HasTagFilter || !reflect.DeepEqual(sibling.TagFilter, seeded[foreign].TagFilter)) ||
					lane == 1 && (sibling.HasTagFilter || sibling.TagFilter != nil) {
					t.Fatal("browser or rejected request changed the sibling alert filter")
				}
			})
		}
	}
}
