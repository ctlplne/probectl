// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import "testing"

func TestNullableScalarTypes(t *testing.T) {
	g := generator{}
	s := &schema{Type: []any{"integer", "null"}}

	if got := g.goType(s); got != "*int" {
		t.Fatalf("goType(nullable integer) = %q, want *int", got)
	}
	if got := g.tsType(s); got != "number | null" {
		t.Fatalf("tsType(nullable integer) = %q, want number | null", got)
	}
}

func TestTSEnumArrayParenthesizesItemUnion(t *testing.T) {
	g := generator{}
	s := &schema{
		Type: "array",
		Items: &schema{
			Type: "string",
			Enum: []any{"flow", "changes"},
		},
	}

	if got := g.tsType(s); got != `("flow" | "changes")[]` {
		t.Fatalf("tsType(enum array) = %q, want parenthesized item union", got)
	}
}
