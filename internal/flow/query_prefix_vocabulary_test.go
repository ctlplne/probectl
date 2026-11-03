// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
)

func TestPrefixTagVocabularyKeepsIndependentSidesAndOwnedInputs(t *testing.T) {
	tenant, id := uuid.NewString(), uuid.NewString()
	vocabulary, err := NewTagQueryVocabulary(tenant, []tags.Definition{{TenantID: tenant, ID: id, Key: "customer"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct{ field, key, column string }{{"tag.src_prefix.customer", "src_prefix.customer", "src_addr"}, {"tag.dst_prefix.customer", "dst_prefix.customer", "dst_addr"}} {
		field, ok := vocabulary.Lookup(side.field)
		if !ok || field.TagID != id || field.TagKey != side.key || field.Column != side.column || field.Permission != "entities.read" || field.Type != QueryText {
			t.Fatalf("source/destination prefix field is unavailable: %s", side.field)
		}
		if _, ok := LookupQueryField(side.field); ok {
			t.Fatal("tenant prefix vocabulary entered global query grammar")
		}
	}
	dimensions := []string{"tag.customer", "tag.device.customer", "tag.agent.customer", "tag.in_interface.customer", "tag.out_interface.customer", "tag.src_prefix.customer", "tag.dst_prefix.customer", "protocol"}
	plan := QueryPlan{GroupBy: dimensions, MatrixWith: dimensions, View: "matrix", Filter: &QueryFilterGroup{Match: "all", Groups: []QueryFilterGroup{{Mode: "exclude", Match: "any", Conditions: []QueryPredicate{{Field: "tag.src_prefix.customer", Op: QueryRegex, Values: []string{"^excluded"}}, {Field: "tag.dst_prefix.customer", Op: QueryEqual, Values: []string{"other"}}}}}}}
	if _, err := NormalizeQueryPlanWithVocabulary(plan, time.Now(), vocabulary); err != nil {
		t.Fatalf("full native dimension/matrix/filter reach rejected prefix fields: %v", err)
	}
	if _, err := NormalizeQueryPlan(plan, time.Now()); err == nil {
		t.Fatal("prefix fields bypassed tenant vocabulary")
	}
	permissions := QueryPlanPermissionsWithVocabulary(plan, vocabulary)
	for _, permission := range []string{"tags.read", "metrics.read", "agent.read", "entities.read"} {
		if !slices.Contains(permissions, permission) {
			t.Fatalf("mixed source plan lost %s", permission)
		}
	}
	ids, err := QueryViewTagIDs(plan, vocabulary)
	if err != nil || len(ids) != 7 || ids["tag.src_prefix.customer"] != id || ids["tag.dst_prefix.customer"] != id {
		t.Fatal("prefix saved field identities collapsed")
	}
}
