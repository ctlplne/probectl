// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSightlinePreviewUsesOnlyExplicitlyMappedCustomerColumns(t *testing.T) {
	const export = "\ufeffLocal object key,Local network,Local display name,Unmapped private field\r\n" +
		"site-alpha,192.0.2.0/24,\"Site, alpha\",discard-example\r\n" +
		"site-alpha,2001:db8::/48,\"Site, alpha\",discard-other\r\n"
	mapping := SightlineColumnMapping{ExternalID: "Local object key", Prefix: "Local network", Label: "Local display name"}
	got, err := ParseSightlineExport(t.Context(), strings.NewReader(export), mapping)
	if err != nil || len(got.Prefixes) != 2 || got.Mapping != mapping ||
		got.Prefixes[0] != (SightlinePrefixCandidate{Row: 1, ExternalID: "site-alpha", Label: "Site, alpha", Prefix: "192.0.2.0/24"}) ||
		got.Prefixes[1].Prefix != "2001:db8::/48" {
		t.Fatal("the explicit header mappings lost a canonical object or its scope", got, err)
	}
	raw, err := json.Marshal(got)
	if err != nil || strings.Contains(string(raw), "discard") {
		t.Fatal("an unmapped column survived the preview", err)
	}
}

func TestSightlinePreviewRefusesAmbiguousRowsWithoutReturningPartialPlans(t *testing.T) {
	mapping := SightlineColumnMapping{ExternalID: "Object", Prefix: "Prefix", Label: "Name"}
	cases := []struct{ name, input string }{
		{"unmapped header", "ID,Prefix,Name\nkey,192.0.2.0/24,Site\n"},
		{"duplicate header", "Object,Prefix,Prefix,Name\nkey,192.0.2.0/24,192.0.2.0/24,Site\n"},
		{"host bits", "Object,Prefix,Name\nkey,192.0.2.2/24,Site\n"},
		{"conflicting labels", "Object,Prefix,Name\nkey,192.0.2.0/24,Site\nkey,2001:db8::/32,Other\n"},
		{"duplicate retained prefix", "Object,Prefix,Name\nkey,192.0.2.0/24,Site\nkey,192.0.2.0/24,Site\n"},
		{"formula identifier", "Object,Prefix,Name\n=1+1,192.0.2.0/24,Site\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseSightlineExport(t.Context(), strings.NewReader(tc.input), mapping); !errors.Is(err, ErrInvalidPage) || len(got.Prefixes) != 0 {
				t.Fatal("ambiguous export returned an actionable partial preview", got, err)
			}
		})
	}
}
