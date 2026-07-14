// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"strings"
	"testing"
	"time"
)

func TestExplorerCanonicalCatalogAndPreview(t *testing.T) {
	if got := len(ExplorerTemplates()); got != 10 {
		t.Fatalf("canonical templates = %d, want 10", got)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	q, err := NormalizeExplorerQuery(ExplorerQuery{
		Question: "Show service dependencies", Source: ExplorerTopology,
		Dimensions: []string{"from", "to"}, Groupings: []string{"kind"},
		Measures: []string{"edges"}, Visualization: "topology",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	preview := ExplorerPreview(q)
	for _, want := range []string{"FROM topology", "TIME 2026-07-14T11:00:00Z", "GROUP BY kind", "MEASURE edges", "VIEW topology"} {
		if !strings.Contains(preview, want) {
			t.Fatalf("preview %q missing %q", preview, want)
		}
	}
}

func TestExplorerRejectsSemanticTenantSelectors(t *testing.T) {
	for _, key := range []string{"tenant", "tenant_id", "tenant-id", "tenant.id"} {
		_, err := NormalizeExplorerQuery(ExplorerQuery{
			Question: "top talkers", Source: ExplorerFlow, Filters: map[string]string{key: "foreign"},
		}, time.Now())
		if err == nil || !strings.Contains(err.Error(), "authentication") {
			t.Fatalf("filter %q error = %v", key, err)
		}
	}
}

func TestExplorerAllowsExactTenantScopedChangeID(t *testing.T) {
	query, err := NormalizeExplorerQuery(ExplorerQuery{
		Question: "show this change", Source: ExplorerChanges,
		Filters: map[string]string{"id": "change-path"},
	}, time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("exact change selector: %v", err)
	}
	if query.Filters["id"] != "change-path" {
		t.Fatalf("exact selector was dropped: %+v", query.Filters)
	}
}
