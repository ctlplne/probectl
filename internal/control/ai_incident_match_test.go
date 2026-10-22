// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/incident"
)

// DPR-298: RCA evidence joins a question's subject to an incident the way
// the correlator joined the incident's signals. A hijack of 127.0.0.0/24
// opens the incident on the prefix; the outage alert on 127.0.0.1 joins it.
// "Why is 127.0.0.1 failing?" must then find that incident.
func TestIncidentMatchesJoinsHostsAndPrefixesLikeTheCorrelator(t *testing.T) {
	onPrefix := incident.Incident{Title: "127.0.0.0/24 announced by unexpected AS65021", Target: "127.0.0.0/24", Prefix: "127.0.0.0/24"}
	onHost := incident.Incident{Title: "service down firing", Target: "127.0.0.1"}
	for _, tc := range []struct {
		name           string
		inc            incident.Incident
		target, prefix string
		want           bool
	}{
		{"host inside the incident's prefix", onPrefix, "127.0.0.1", "", true},
		{"the incident's own prefix", onPrefix, "", "127.0.0.0/24", true},
		{"a more-specific of the incident's prefix", onPrefix, "", "127.0.0.0/25", true},
		{"a host outside the incident's prefix", onPrefix, "198.51.100.7", "", false},
		{"an unrelated prefix", onPrefix, "", "198.51.100.0/24", false},
		{"the incident's own host", onHost, "127.0.0.1", "", true},
		{"a prefix holding the incident's host", onHost, "", "127.0.0.0/8", true},
		{"another host", onHost, "127.0.0.2", "", false},
		{"no subject: every incident", onHost, "", "", true},
	} {
		if got := incidentMatches(tc.inc, tc.target, tc.prefix); got != tc.want {
			t.Errorf("%s: incidentMatches(%q/%q, target %q, prefix %q) = %v, want %v",
				tc.name, tc.inc.Target, tc.inc.Prefix, tc.target, tc.prefix, got, tc.want)
		}
	}
}
