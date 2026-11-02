// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
)

func TestTagQueryVocabularyIsTenantBoundAndDoesNotChangeNativeRegistry(t *testing.T) {
	a, b := uuid.NewString(), uuid.NewString()
	id := uuid.NewString()
	vocabulary, err := NewTagQueryVocabulary(a, []tags.Definition{
		{TenantID: a, ID: id, Key: "customer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	field, ok := vocabulary.Lookup(" TAG.CUSTOMER ")
	if !ok || field.TagID != id || field.TagKey != "customer" || field.Permission != "tags.read" ||
		field.Type != QueryText || field.Derived != "tenant_tag" {
		t.Fatalf("tenant tag field was not bound to its definition: %+v, %v", field, ok)
	}
	if _, ok := LookupQueryField("tag.customer"); ok {
		t.Fatal("tenant tag escaped into the process-wide native registry")
	}
	if _, ok := vocabulary.Lookup("tag.other"); ok {
		t.Fatal("unknown tenant tag key was accepted")
	}
	plan := QueryPlan{GroupBy: []string{"tag.customer"}, Filter: &QueryFilterGroup{
		Conditions: []QueryPredicate{{Field: "tag.customer", Op: QueryEqual, Values: []string{"blue"}}},
	}}
	if _, err := NormalizeQueryPlan(plan, time.Now()); err == nil {
		t.Fatal("native-only query normalization admitted a tenant tag")
	}
	if _, err := NormalizeQueryPlanWithVocabulary(plan, time.Now(), vocabulary); err != nil {
		t.Fatalf("tenant-bound query rejected its tag: %v", err)
	}
	permissions := QueryPlanPermissionsWithVocabulary(plan, vocabulary)
	if len(permissions) != 1 || permissions[0] != "tags.read" {
		t.Fatalf("tenant tag query lost permission: %v", permissions)
	}
	prepared, err := PrepareQueryFilterWithVocabulary(plan.Filter, vocabulary)
	if err != nil {
		t.Fatalf("tenant-bound filter rejected its tag: %v", err)
	}
	if !prepared.Matches(func(string) string { return "blue" }) ||
		prepared.Matches(func(string) string { return "red" }) {
		t.Fatal("tenant-bound tag predicate did not match its resolved value")
	}
	field.Operators[0] = QueryBitAnd
	second, ok := vocabulary.Lookup("tag.customer")
	if !ok || second.Operators[0] == QueryBitAnd {
		t.Fatal("caller mutated the tenant query vocabulary")
	}
	fields, err := vocabulary.Fields()
	if err != nil || fields[len(fields)-1].Name != "tag.customer" {
		t.Fatalf("tenant schema omitted its tag field: %+v, %v", fields, err)
	}
	if _, err := NewTagQueryVocabulary(a, []tags.Definition{
		{TenantID: b, ID: id, Key: "customer"},
	}); !errors.Is(err, tags.ErrScopeMismatch) {
		t.Fatalf("foreign tenant definition was accepted: %v", err)
	}
	if _, err := NewTagQueryVocabulary(a, []tags.Definition{
		{TenantID: a, ID: id, Key: "customer"},
		{TenantID: a, ID: uuid.NewString(), Key: "customer"},
	}); !errors.Is(err, tags.ErrConflict) {
		t.Fatalf("duplicate tenant key was accepted: %v", err)
	}
}
