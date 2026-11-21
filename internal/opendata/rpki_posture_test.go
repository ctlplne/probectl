// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestRPKIPostureShowsExactAuthorizationAndMinimalSuggestion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	raw := fmt.Sprintf(`{"metadata":{"generated":%d},"roas":[{"prefix":"192.0.2.0/24","asn":64496,"maxLength":25},{"prefix":"2001:db8::/32","asn":0,"maxLength":128},{"prefix":"2001:db8:4000::/34","asn":64499,"maxLength":64}]}`, now.Unix())
	source, err := rpkiSourceForTest(t, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		prefix         string
		asn            uint32
		at             time.Time
		owned          bool
		status, reason string
		suggested      bool
	}{
		{"192.0.2.0/25", 64496, now, true, "valid", "matching_prefix_and_origin", false},
		{"192.0.2.0/26", 64496, now, true, "invalid", "prefix_length_exceeds_origin_authorization", true},
		{"192.0.2.0/25", 64497, now, false, "invalid", "origin_mismatch", false},
		{"203.0.113.0/24", 64496, now, true, "not_found", "no_covering_assertion", true},
		{"2001:db8::/48", 64496, now, true, "invalid", "as0_denial_or_insufficient_length", false},
		{"2001:db8:4000::/48", 64496, now, true, "invalid", "origin_mismatch", false},
		{"2001:db8:4000::/48", 64499, now, true, "valid", "matching_prefix_and_origin", false},
		{"192.0.2.0/25", 64496, now.Add(2 * time.Hour), true, "unknown", "validator_unavailable", false},
	} {
		t.Run(c.reason, func(t *testing.T) {
			prefix := netip.MustParsePrefix(c.prefix)
			got, err := AssessRPKIPosture(t.Context(), source.snapshotAt(c.at), c.at, prefix, &c.asn, c.owned, 1<<20, 1<<20)
			if err != nil || got.Status != c.status || got.Reason != c.reason || (got.Suggestion != nil) != c.suggested {
				t.Fatal("posture lost validated state or ownership", got, err)
			}
			if got.Suggestion != nil && (got.Suggestion.Prefix != prefix || got.Suggestion.OriginASN != c.asn) {
				t.Fatal("suggestion broadened the prefix or origin", got.Suggestion)
			}
		})
	}
}
