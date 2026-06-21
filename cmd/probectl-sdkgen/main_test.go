// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
