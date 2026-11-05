// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestFlowExplorerStoredFieldGrammar(t *testing.T) {
	_, err := NormalizeExplorerQuery(ExplorerQuery{
		Question: "Traffic by source address and destination port", Source: ExplorerFlow,
		Dimensions: []string{"src_addr", "dst_port"}, Groupings: []string{"src_addr", "dst_port"},
		Measures: []string{"bytes", "packets", "flows"}, Limit: 25,
	}, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("stored flow fields must be queryable: %v", err)
	}
}

func TestFlowExplorerTagFieldRequiresTenantVocabulary(t *testing.T) {
	tenant := uuid.NewString()
	vocabulary, err := flow.NewTagQueryVocabulary(tenant, []tags.Definition{
		{TenantID: tenant, ID: uuid.NewString(), Key: "customer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	query := ExplorerQuery{Source: ExplorerFlow, Dimensions: []string{"tag.customer"},
		Filters: map[string]string{"tag.customer": "blue"}}
	now := time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)
	if _, err := ExplorerFlowSpec(query, now); err == nil {
		t.Fatal("native flow envelope accepted a tenant tag without a vocabulary")
	}
	plan, err := ExplorerFlowSpecWithVocabulary(query, now, vocabulary)
	if err != nil || len(plan.GroupBy) != 1 || plan.GroupBy[0] != "tag.customer" {
		t.Fatalf("tenant flow envelope lost its tag: %+v, %v", plan, err)
	}
	if _, err := NormalizeExplorerQuery(query, now); err == nil {
		t.Fatal("native-only public normalizer accepted tenant tag")
	}
	query.Question = "Group tenant flows by customer"
	normalized, err := NormalizeExplorerQueryWithVocabulary(query, now, vocabulary)
	if err != nil || normalized.Flow == nil || normalized.Flow.GroupBy[0] != "tag.customer" {
		t.Fatalf("public normalizer lost tenant tag: %+v, %v", normalized, err)
	}
}

func TestFlowExplorerRejectsUnrepresentableSelectedRows(t *testing.T) {
	_, err := NormalizeExplorerQuery(ExplorerQuery{
		Question: "Traffic by site", Source: ExplorerFlow,
		Dimensions: []string{"src_addr"}, Measures: []string{"bps"}, Limit: 2147483648,
	}, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("unrepresentable selected count must refuse, never silently clamp")
	}
}
