// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"fmt"
	"net/http"
	"testing"
)

func proveReleaseTagAdmin(t *testing.T, root, certificate string, tenants [2]api, sessions []releaseSession) {
	t.Helper()
	const card = "[data-tenant-tags]"
	for _, theme := range []string{"light", "dark"} {
		initial := "release_admin_initial_" + theme
		var stableIDs [2]string
		for i, tenant := range tenants {
			var created struct {
				ID string `json:"id"`
			}
			tenant.json(t, http.StatusCreated, http.MethodPost, "/v1/tags", map[string]string{"key": initial}, &created)
			stableIDs[i] = created.ID
		}
		if stableIDs[0] == "" || stableIDs[1] == "" || stableIDs[0] == stableIDs[1] {
			t.Fatal("same-key tags did not retain separate tenant identities")
		}
		key := func(lane int, operation string) string {
			return fmt.Sprintf("release_admin_%s_%d_%s", operation, lane, theme)
		}
		for i, tenant := range tenants {
			created, renamed := key(i, "created"), key(i, "renamed")
			foreign := []string{stableIDs[1-i], key(1-i, "created"), key(1-i, "renamed")}
			t.Run(fmt.Sprintf("%d/%s", i, theme), func(t *testing.T) {
				renderReleaseBrowser(t, root, map[string]any{
					"url": tenant.base + "/ui/admin", "theme": theme,
					"cookies":        []map[string]string{{"name": "probectl_session", "value": sessions[i].Cookie}},
					"trustCertFiles": []string{certificate}, "timeoutMs": 60_000,
					"expect": []string{"Tenant tag definitions", initial, stableIDs[i]},
					"absent": foreign,
					"steps": []map[string]any{
						{"fill": card + " form input", "value": created},
						{"click": "Create key", "within": card, "expectWithin": card,
							"expect": []string{"Tag key created.", created}},
						{"click": "Rename tag " + initial, "within": card, "expectWithin": card,
							"expect": []string{"Rename " + initial}},
						{"fill": card + " form:has-text('Rename " + initial + "') input", "value": renamed},
						{"click": "Save name", "within": card, "expectWithin": card,
							"expect": []string{renamed, stableIDs[i]}, "absent": append([]string{initial}, foreign...)},
					},
				})
				verifyReleaseAdminTags(t, tenants, i, initial, created, renamed, stableIDs)
			})
		}
	}
}

func verifyReleaseAdminTags(t *testing.T, tenants [2]api, lane int, initial, created, renamed string, stableIDs [2]string) {
	t.Helper()
	lookup := func(reader api) map[string]string {
		var listing struct {
			Items []struct {
				ID  string `json:"id"`
				Key string `json:"key"`
			} `json:"items"`
		}
		reader.json(t, http.StatusOK, http.MethodGet, "/v1/tags", nil, &listing)
		ids := make(map[string]string, len(listing.Items))
		for _, item := range listing.Items {
			ids[item.Key] = item.ID
		}
		return ids
	}
	own, sibling := lookup(tenants[lane]), lookup(tenants[1-lane])
	if own[created] == "" || own[renamed] != stableIDs[lane] || own[initial] != "" {
		t.Fatal("Admin did not persist the owned creation and stable rename")
	}
	if sibling[created] != "" || sibling[renamed] != "" {
		t.Fatal("Admin exposed an owned mutation to the sibling")
	}
	// The first browser must leave the sibling's identical key at its
	// own ID. The second browser executes after the first has renamed it.
	if lane == 0 && sibling[initial] != stableIDs[1] {
		t.Fatal("Admin changed the sibling's same-key tag")
	}
}
