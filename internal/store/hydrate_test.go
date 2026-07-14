// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/change"
)

// fakeRow drives the unexported scan* hydrators without a database: each Scan
// target gets the matching positional value (assignable or convertible).
type fakeRow struct{ vals []any }

func (r fakeRow) Scan(dst ...any) error {
	if len(dst) != len(r.vals) {
		return fmt.Errorf("fakeRow: %d scan targets, have %d vals", len(dst), len(r.vals))
	}
	for i, d := range dst {
		dv := reflect.ValueOf(d).Elem()
		sv := reflect.ValueOf(r.vals[i])
		if !sv.IsValid() {
			continue // leave the zero value
		}
		switch {
		case sv.Type().AssignableTo(dv.Type()):
			dv.Set(sv)
		case sv.Type().ConvertibleTo(dv.Type()):
			dv.Set(sv.Convert(dv.Type()))
		default:
			return fmt.Errorf("fakeRow: vals[%d] %T not assignable to %s", i, r.vals[i], dv.Type())
		}
	}
	return nil
}

// CODE-005: a corrupt JSON attributes column must FAIL the row read loudly, not
// silently hydrate an empty map — for ABAC an empty subject matches every
// request and could flip a deny-override policy open. Valid rows still load.
func TestScanPolicySurfacesCorruptJSON(t *testing.T) {
	cols := func(subj, res []byte) []any {
		return []any{"pid", "name", "permit", "metrics.read", subj, res, 10, true}
	}

	// Valid subject/resource hydrate.
	var p auth.Policy
	if err := scanPolicy(fakeRow{cols([]byte(`{"team":"net"}`), []byte(`{"env":"prod"}`))}, &p); err != nil {
		t.Fatalf("valid policy must load: %v", err)
	}
	if p.Subject["team"] != "net" || p.Resource["env"] != "prod" {
		t.Fatalf("attributes not hydrated: %+v", p)
	}

	// Corrupt subject fails loudly (not an empty, permissive map).
	if err := scanPolicy(fakeRow{cols([]byte("{not json"), nil)}, &auth.Policy{}); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("corrupt subject must error: %v", err)
	}
	// Corrupt resource fails loudly too.
	if err := scanPolicy(fakeRow{cols([]byte(`{"team":"net"}`), []byte("{bad"))}, &auth.Policy{}); err == nil || !strings.Contains(err.Error(), "resource") {
		t.Fatalf("corrupt resource must error: %v", err)
	}
}

func TestScanUserSurfacesCorruptJSON(t *testing.T) {
	cols := func(attrs []byte) []any {
		return []any{"uid", "t1", "e@x", "Name", "active", (*string)(nil), (*string)(nil), attrs, time.Now(), time.Now()}
	}
	var u User
	if err := scanUser(fakeRow{cols([]byte(`{"dept":"neteng"}`))}, &u); err != nil {
		t.Fatalf("valid user must load: %v", err)
	}
	if u.Attributes["dept"] != "neteng" {
		t.Fatalf("attributes not hydrated: %+v", u)
	}
	if err := scanUser(fakeRow{cols([]byte("{bad"))}, &User{}); err == nil || !strings.Contains(err.Error(), "attributes") {
		t.Fatalf("corrupt user attributes must error: %v", err)
	}
}

func TestScanChangeSurfacesCorruptJSON(t *testing.T) {
	cols := func(attrs []byte) []any {
		return []any{"cid", "t1", "github", "deploy", "title", "sum", "tgt", "pfx", "actor", "ref", "url", attrs, time.Now(), time.Now()}
	}
	var c change.Event
	if err := scanChange(fakeRow{cols([]byte(`{"pr":"42"}`))}, &c); err != nil {
		t.Fatalf("valid change must load: %v", err)
	}
	if c.Attributes["pr"] != "42" {
		t.Fatalf("attributes not hydrated: %+v", c)
	}
	if err := scanChange(fakeRow{cols([]byte("{bad"))}, &change.Event{}); err == nil || !strings.Contains(err.Error(), "attributes") {
		t.Fatalf("corrupt change attributes must error: %v", err)
	}
}
