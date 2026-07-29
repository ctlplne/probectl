// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"strings"
	"testing"
)

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

func TestGoSDKResponseBodyLimitGenerated(t *testing.T) {
	g := generator{doc: &document{Components: components{Schemas: map[string]*schema{}}}}
	generated, err := g.goSDK(nil)
	if err != nil {
		t.Fatalf("generate Go SDK: %v", err)
	}
	source := string(generated)
	for _, want := range []string{
		"const MaxResponseBodyBytes int64 = httpbody.MaxClientResponseBodyBytes",
		"const MaxErrorResponseBodyBytes int64 = httpbody.MaxClientErrorResponseBodyBytes",
		"data, err := httpbody.ReadLimited(resp.Body, limit)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("generated SDK missing bounded response code %q", want)
		}
	}
	if strings.Contains(source, "io.ReadAll(resp.Body)") {
		t.Fatal("generated SDK retained an unbounded response-body read")
	}
}
