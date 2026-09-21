// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"strings"
	"testing"
	"time"

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
