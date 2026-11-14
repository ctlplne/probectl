// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package change

import (
	"testing"
	"time"
)

func TestBoundConfigCandidatesRequireExactCanonicalDeviceAcrossRenames(t *testing.T) {
	at := time.Now().UTC()
	bound := Event{ID: "original", Target: "old-name", OccurredAt: at, Config: &ConfigReference{Binding: &ConfigBindingReference{ContextID: "owned-context", DeviceEntityID: "owned-device"}}}
	other := Event{ID: "other", Target: "current-name", OccurredAt: at, Config: &ConfigReference{Binding: &ConfigBindingReference{ContextID: "other-context", DeviceEntityID: "owned-device"}}}
	events := []Event{bound, other}
	if got := Candidates(events, "current-name", "", at, time.Hour); len(got) != 0 {
		t.Fatal("name-only correlation attached a bound source", got)
	}
	got := CandidatesForIdentity(events, "current-name", "", "owned-context", "owned-device", at, time.Hour)
	if len(got) != 1 || got[0].Event.ID != "original" || got[0].Event.Target != "old-name" {
		t.Fatal("canonical correlation crossed contexts or rewrote the original presentation", got)
	}
	if got := CandidatesForIdentity(events, "current-name", "", "owned-context", "other-device", at, time.Hour); len(got) != 0 {
		t.Fatal("same-name device received another canonical device's config", got)
	}
}
