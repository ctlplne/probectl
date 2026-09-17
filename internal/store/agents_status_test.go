// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"testing"
	"time"
)

// DPR-082: "online" is a claim about now. On the lab seven agents last seen
// three to five hours earlier still read online; a bus collector publishing
// every 10 s read online only because nothing ever said otherwise.
func TestDeriveStatusFollowsFreshness(t *testing.T) {
	now := time.Date(2026, 9, 17, 11, 27, 0, 0, time.UTC)
	fresh := now.Add(-40 * time.Second)
	stale := now.Add(-5 * time.Hour)
	edge := now.Add(-AgentOnlineWindow)
	for _, tc := range []struct {
		name, stored string
		last         *time.Time
		want         string
	}{
		{"fresh heartbeat", "online", &fresh, "online"},
		{"seen five hours ago", "online", &stale, "offline"},
		{"exactly at the window", "online", &edge, "online"},
		{"never seen", "online", nil, "registered"},
		{"registered passes through", "registered", nil, "registered"},
		{"revoked passes through", "revoked", &fresh, "revoked"},
		{"offline stays offline even if last_seen is recent", "offline", &fresh, "offline"},
	} {
		if got := deriveStatus(tc.stored, tc.last, now); got != tc.want {
			t.Errorf("%s: deriveStatus(%q) = %q, want %q", tc.name, tc.stored, got, tc.want)
		}
	}
}
