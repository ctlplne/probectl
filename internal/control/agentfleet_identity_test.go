// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
)

// DPR-176: the fleet view knew when an agent last spoke and what version it ran,
// and nothing about the certificate that lets it speak at all. Rotation failing
// is the one fault that kills an agent silently — it keeps working on the
// identity it holds, then stops for good — and the view reported "ready"
// throughout, then "stale", never naming the cause.
func TestFleetIdentityStateNamesTheCredentialWindow(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	issued := now.Add(-24 * time.Hour) // the lab's SVID lifetime

	for _, tc := range []struct {
		name       string
		identity   *store.AgentIdentityWindow
		wantState  string
		wantSaidIn string
	}{
		{
			name:       "no recorded identity is unknown, never assumed healthy",
			identity:   nil,
			wantState:  "unknown",
			wantSaidIn: "cannot be read",
		},
		{
			name:       "fresh identity is current",
			identity:   &store.AgentIdentityWindow{IssuedAt: now.Add(-time.Hour), NotAfter: now.Add(23 * time.Hour)},
			wantState:  "current",
			wantSaidIn: "valid until",
		},
		{
			name:       "past three quarters of its life with no rotation is overdue",
			identity:   &store.AgentIdentityWindow{IssuedAt: now.Add(-23 * time.Hour), NotAfter: now.Add(time.Hour)},
			wantState:  "renewal_overdue",
			wantSaidIn: "75%",
		},
		{
			name:       "past NotAfter is expired",
			identity:   &store.AgentIdentityWindow{IssuedAt: issued.Add(-24 * time.Hour), NotAfter: issued},
			wantState:  "expired",
			wantSaidIn: "cannot rotate itself",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, reason := fleetIdentityState(tc.identity, now)
			if state != tc.wantState {
				t.Fatalf("state = %q, want %q (reason: %s)", state, tc.wantState, reason)
			}
			if reason == "" {
				t.Fatal("every identity state must carry an operator-readable reason")
			}
			if !strings.Contains(reason, tc.wantSaidIn) {
				t.Fatalf("reason %q does not say %q", reason, tc.wantSaidIn)
			}
		})
	}
}

// An expired identity is the CAUSE that a stale heartbeat is only a symptom of,
// so the fleet verdict must name it and send the operator to re-enrollment
// rather than to the transport.
func TestFleetReadinessNamesTheExpiredIdentityRatherThanTheSilence(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	seen := now.Add(-3 * time.Hour) // silent for hours, exactly as the lab agent was
	row := store.Agent{
		ID: "agent-1", TenantID: "tenant-a", Name: "browser-1",
		AgentVersion: "v1.4.2", Status: "offline", LastSeenAt: &seen,
		Capabilities: []string{"browser-rendered"},
	}
	identities := map[string]store.AgentIdentityWindow{
		"agent-1": {IssuedAt: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour)},
	}

	views, err := buildFleetAgentViews([]store.Agent{row}, nil, identities, "v1.4.2", now)
	if err != nil {
		t.Fatal(err)
	}
	got := views[0]
	if got.IdentityState != "expired" {
		t.Fatalf("identity_state = %q, want expired", got.IdentityState)
	}
	if got.IdentityExpiresAt == nil || !got.IdentityExpiresAt.Equal(identities["agent-1"].NotAfter) {
		t.Fatalf("identity_expires_at not reported: %v", got.IdentityExpiresAt)
	}
	if got.ReadinessState != "identity_expired" {
		t.Fatalf("readiness_state = %q, want identity_expired (heartbeat state was %q)", got.ReadinessState, got.HeartbeatState)
	}
	if got.NextSafeAction.Kind != "reenroll_identity" {
		t.Fatalf("next safe action = %q, want reenroll_identity", got.NextSafeAction.Kind)
	}

	// And a healthy agent with a fresh identity is still plainly ready.
	fresh := now.Add(-time.Minute)
	row.Status, row.LastSeenAt = "online", &fresh
	identities["agent-1"] = store.AgentIdentityWindow{IssuedAt: now.Add(-time.Hour), NotAfter: now.Add(23 * time.Hour)}
	views, err = buildFleetAgentViews([]store.Agent{row}, nil, identities, "v1.4.2", now)
	if err != nil {
		t.Fatal(err)
	}
	if views[0].ReadinessState != "ready" || views[0].IdentityState != "current" {
		t.Fatalf("healthy agent reported %s/%s", views[0].ReadinessState, views[0].IdentityState)
	}
}
