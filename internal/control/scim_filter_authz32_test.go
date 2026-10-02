// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/store"
)

// TestSCIMUserFilterFailsClosedAUTHZ32 pins the fail-closed filter contract for
// the Users list: an empty filter lists all, `userName eq`/`externalId eq` map
// to exact-match store filters, and anything else is REJECTED (so the list
// handler answers 400 invalidFilter instead of the old fail-open full list).
// References the new scimUserFilter/store.UserFilter symbols, so the baseline
// fails to build; the observable baseline RED (an unsupported filter returns
// every user) is proven by the integration test.
func TestSCIMUserFilterFailsClosedAUTHZ32(t *testing.T) {
	cases := []struct {
		raw     string
		want    store.UserFilter
		wantErr bool
	}{
		{raw: "", want: store.UserFilter{}},
		{raw: `userName eq "ada@x.com"`, want: store.UserFilter{UserName: "ada@x.com"}},
		{raw: `  userName eq "ada@x.com"  `, want: store.UserFilter{UserName: "ada@x.com"}}, // outer trim
		{raw: `externalId eq "ext-1"`, want: store.UserFilter{ExternalID: "ext-1"}},
		{raw: `EXTERNALID EQ "ext-1"`, want: store.UserFilter{ExternalID: "ext-1"}}, // case-insensitive attr/op
		{raw: `displayName eq "x"`, wantErr: true},                                  // unsupported attribute
		{raw: `userName sw "a"`, wantErr: true},                                     // unsupported operator
		{raw: `userName co "a"`, wantErr: true},
		{raw: `userName eq "a" or userName eq "b"`, wantErr: true}, // compound → not half-applied
		{raw: `userName pr`, wantErr: true},
		{raw: `anything`, wantErr: true},
		{raw: `userName eq a`, wantErr: true}, // unquoted value
	}
	for _, tc := range cases {
		got, err := scimUserFilter(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("scimUserFilter(%q) = %+v, want error (fail closed)", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("scimUserFilter(%q) errored: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("scimUserFilter(%q) = %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}

// TestSCIMGroupFilterFailsClosedAUTHZ32 is the Groups-list counterpart: only
// `displayName eq "…"` is supported; an empty filter lists all; anything else
// is rejected.
func TestSCIMGroupFilterFailsClosedAUTHZ32(t *testing.T) {
	cases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "", want: ""},
		{raw: `displayName eq "Engineers"`, want: "Engineers"},
		{raw: `displayName eq "Platform Engineers"`, want: "Platform Engineers"}, // value may contain spaces
		{raw: `userName eq "x"`, wantErr: true},
		{raw: `displayName sw "E"`, wantErr: true},
		{raw: `displayName eq "a" or displayName eq "b"`, wantErr: true},
	}
	for _, tc := range cases {
		got, err := scimGroupFilter(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("scimGroupFilter(%q) = %q, want error (fail closed)", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("scimGroupFilter(%q) errored: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("scimGroupFilter(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}
