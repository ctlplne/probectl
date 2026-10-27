// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

func TestValidateIncidentJournalRequest(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		request appendIncidentJournalRequest
		wantErr bool
	}{
		{name: "plain inert text", request: appendIncidentJournalRequest{
			Kind: "note", Body: `<script>tool.call("reboot")</script> remains plain text`,
		}},
		{name: "checkpoint", request: appendIncidentJournalRequest{
			Kind: "checkpoint", Body: "routing change confirmed",
			Citation: &incidentJournalCitationRequest{ShareID: "share_abc", EvidenceID: "E1"},
		}},
		{name: "empty", request: appendIncidentJournalRequest{Kind: "note"}, wantErr: true},
		{name: "note with citation", request: appendIncidentJournalRequest{
			Kind: "note", Body: "note",
			Citation: &incidentJournalCitationRequest{ShareID: "share_abc", EvidenceID: "E1"},
		}, wantErr: true},
		{name: "checkpoint without citation", request: appendIncidentJournalRequest{
			Kind: "checkpoint", Body: "checkpoint",
		}, wantErr: true},
		{name: "too long", request: appendIncidentJournalRequest{
			Kind: "note", Body: strings.Repeat("a", maxIncidentJournalRunes+1),
		}, wantErr: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateIncidentJournalRequest(&tc.request)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate error = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestIncidentJournalExpiryUsesTenantObjectRetention(t *testing.T) {
	oneDay := 1
	srv := &Server{}
	srv.tenantLife = &fakeTenantLifecycle{
		policy: tenantlife.RetentionPolicy{ObjectRetentionDays: &oneDay},
	}
	before := time.Now().UTC()
	expires, err := srv.incidentJournalExpiry(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if expires.Before(before.Add(23*time.Hour)) || expires.After(before.Add(25*time.Hour)) {
		t.Fatalf("journal expiry = %v, want tenant-bounded one-day retention", expires)
	}
}

func TestJournalCitationPreservesUnknownObservationTime(t *testing.T) {
	for _, at := range []time.Time{{}, time.Date(2026, 10, 27, 3, 37, 0, 0, time.UTC)} {
		evidence := ai.Evidence{ID: "topology-evidence", Domain: ai.DomainTopology, Plane: "topology", Title: "node", OccurredAt: at}
		citation := journalCitationFromEvidence(incidentJournalCitationRequest{ShareID: "owned-share", EvidenceID: evidence.ID}, evidence)
		raw, err := json.Marshal(citation)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		value, present := fields["occurred_at"]
		if at.IsZero() {
			if present {
				t.Fatalf("timeless evidence invents timestamp: %s", raw)
			}
		} else if !present || value != at.Format(time.RFC3339) {
			t.Fatalf("recorded timestamp lost: %s", raw)
		}
		if citation.State != "available" || citation.EvidenceID != evidence.ID {
			t.Fatalf("citation identity changed: %+v", citation)
		}
	}
}
