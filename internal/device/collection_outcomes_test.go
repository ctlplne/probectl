// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package device

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCollectionOutcomeStableStateMatrixAndRedaction(t *testing.T) {
	now := time.Now().UTC()
	base := CollectionOutcome{
		TenantID: "tenant-a", AgentID: "agent-a", ConfiguredTarget: "router-a.internal",
		Protocol: NeighborProtocolLLDP, LastAttemptAt: &now,
		State: CollectionStateFailed, Reason: CollectionReasonPollFailed,
		NextAction: CollectionActionVerifyLocalAccess,
	}
	if _, err := ValidateCollectionOutcome(base); err != nil {
		t.Fatalf("valid failed receipt: %v", err)
	}
	bad := base
	bad.State = CollectionStateHealthyEmpty
	if _, err := ValidateCollectionOutcome(bad); err == nil {
		t.Fatal("healthy_empty accepted a failed reason/action matrix")
	}
	success := base
	success.State, success.Reason = CollectionStateOKWithRows, CollectionReasonRowsObserved
	success.NextAction, success.RowCount, success.LastSuccessAt = CollectionActionReviewEvidence, 1, &now
	valid, err := ValidateCollectionOutcome(success)
	if err != nil {
		t.Fatalf("valid successful receipt: %v", err)
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ToLower(string(raw))
	for _, forbidden := range []string{"tenant-a", "community", "credential", "password", "varbind", "raw_error"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("receipt JSON leaked forbidden field/value %q: %s", forbidden, raw)
		}
	}
}

func TestMemoryCollectionOutcomeStoreTenantScopedAndMonotonic(t *testing.T) {
	store := NewMemoryCollectionOutcomeStore()
	now := time.Now().UTC()
	write := func(tenant, target string, at time.Time, state, reason, action string) {
		t.Helper()
		outcome := CollectionOutcome{
			TenantID: tenant, AgentID: "agent-a", ConfiguredTarget: target,
			Protocol: NeighborProtocolLLDP, LastAttemptAt: &at,
			State: state, Reason: reason, NextAction: action,
		}
		if state == CollectionStateHealthyEmpty {
			outcome.LastSuccessAt = &at
		}
		if err := store.UpsertCollectionOutcome(context.Background(), tenant, outcome); err != nil {
			t.Fatal(err)
		}
	}
	write("tenant-a", "router-a", now, CollectionStateHealthyEmpty,
		CollectionReasonNoRowsObserved, CollectionActionReviewConfiguration)
	write("tenant-b", "secret-router-b", now, CollectionStateFailed,
		CollectionReasonPollFailed, CollectionActionVerifyLocalAccess)
	write("tenant-a", "router-a", now.Add(-time.Minute), CollectionStateFailed,
		CollectionReasonPollFailed, CollectionActionVerifyLocalAccess)

	rows, _, err := store.ListCollectionOutcomes(context.Background(), "tenant-a", CollectionOutcomeFilter{})
	if err != nil || len(rows) != 1 || rows[0].State != CollectionStateHealthyEmpty ||
		rows[0].ConfiguredTarget == "secret-router-b" {
		t.Fatalf("tenant-a monotonic rows=%+v err=%v", rows, err)
	}
}
