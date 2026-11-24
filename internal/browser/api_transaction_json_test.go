// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"errors"
	"testing"
)

func TestAPITransactionJSONSelectorsPreserveOrderAndBounds(t *testing.T) {
	const document = `{
	  "items": [{"state":"pending","detail":{"ready":false,"limit":null}},{"state":"ready","detail":{"ready":true,"limit":12}}],
	  "meta": {"state":"retained"},
	  "owner's name": "operator",
	  "display\"label": "local"
	}`
	ctx := t.Context()
	body, err := decodeAPIJSON(ctx, []byte(document))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ path, expected string }{
		{`$['owner\'s name', "display\"label"]`, `["operator","local"]`},
		{`$..state`, `["pending","ready","retained"]`},
		{`$.items[1,-2].state`, `["ready","pending"]`},
		{`$.items[::-1].detail`, `[{"limit":12,"ready":true},{"limit":null,"ready":false}]`},
		{`$.items[9,::0]`, `[]`},
	} {
		t.Run(test.path, func(t *testing.T) {
			segments, err := parseAPIJSONPath(test.path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := selectAPIJSON(ctx, body, segments, 256)
			if err != nil {
				t.Fatal(err)
			}
			want, err := decodeAPIJSON(ctx, []byte(test.expected))
			if err != nil {
				t.Fatal(err)
			}
			if equal, err := equalAPIJSON(ctx, got, want); err != nil || !equal {
				t.Fatalf("selection got %v, want %v (%v)", got, want, err)
			}
		})
	}
	for _, path := range []string{`$.['items']`, `$.items[01]`, `$.items[::bad]`, `$.items['unterminated]`} {
		if _, err := parseAPIJSONPath(path); !errors.Is(err, errAPIJSONPath) {
			t.Fatalf("invalid selector %q got %v", path, err)
		}
	}
	for _, raw := range []string{`{"state":"first","state":"second"}`, `{"state":"first"} {"state":"second"}`} {
		if _, err := decodeAPIJSON(ctx, []byte(raw)); !errors.Is(err, errAPIJSONDocument) {
			t.Fatalf("ambiguous JSON got %v", err)
		}
	}
	segments, err := parseAPIJSONPath(`$..*`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectAPIJSON(ctx, body, segments, 2); !errors.Is(err, errAPIJSONWork) {
		t.Fatalf("recursive query escaped its work budget: %v", err)
	}
}
