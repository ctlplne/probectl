// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func membershipManifest(at time.Time, rows []ixMembershipRecord) map[string]any {
	return map[string]any{"version": 1, "object": "netixlan", "observed_at": at, "complete": true, "record_count": len(rows), "data": rows}
}

func membershipFile(t *testing.T, manifest map[string]any) string {
	t.Helper()
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return ixPrefixFile(t, body)
}

// Synthetic source data, not a permitted PeeringDB download or live session.
func TestIXMembershipCacheKeepsCompletePortsExactSelectorsAndOriginalFreshness(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	const count = 50_001
	rows := make([]ixMembershipRecord, count)
	for i := range rows {
		rows[i] = ixMembershipRecord{ID: int64(i + 1), IXID: 7, LANID: 11, ASN: 64500, Status: "ok", Operational: true}
	}
	rows = append(rows, ixMembershipRecord{ID: count + 1, IXID: 7, LANID: 12, ASN: ^uint32(0), Status: "ok", Operational: true})
	for i, status := range []string{"pending", "deleted", "ok"} {
		rows = append(rows, ixMembershipRecord{ID: count + int64(i) + 2, IXID: 7, LANID: 11, ASN: 64500, Status: status, Operational: false})
	}
	source, err := LoadPeeringDBIXMemberships(t.Context(), membershipFile(t, membershipManifest(at, rows)), time.Hour, 256<<20, time.Now())
	if err != nil {
		t.Fatal("complete membership source was refused", err)
	}
	en := NewEnricher(nil)
	en.Register(source)
	snapshot := en.IXMemberships(time.Now())
	values, err := snapshot.Members(t.Context(), 64500, 7, 11, 32<<20, 32<<20)
	if err != nil || len(values) != count || !strings.Contains(values[count-1], "/50001/snapshot/") {
		t.Fatal("complete IX membership lost ports or included inactive records", len(values), err)
	}
	values[0] = "changed caller result"
	again, err := snapshot.Members(t.Context(), 64500, 7, 11, 32<<20, 32<<20)
	if err != nil || again[0] == values[0] || !snapshot.SameGeneration(en.IXMemberships(time.Now())) || !snapshot.ObservedAt.Equal(at) || !snapshot.ValidUntil.Equal(at.Add(time.Hour)) {
		t.Fatal("membership read changed ownership, generation or original clock", err)
	}
	for _, selector := range []ixMembershipKey{{64500, 8, 11}, {64500, 7, 12}, {64501, 7, 11}} {
		if got, err := snapshot.Members(t.Context(), selector.asn, selector.ix, selector.ixlan, 1<<20, 1<<20); err != nil || len(got) != 0 {
			t.Fatal("membership borrowed another ASN, IX or LAN", selector, err)
		}
	}
	if got, err := snapshot.Members(t.Context(), ^uint32(0), 7, 12, 1<<20, 1<<20); err != nil || len(got) != 1 {
		t.Fatal("membership narrowed the full ASN range", err)
	}
	if got, err := snapshot.Members(t.Context(), 64500, 7, 11, 1024, 1024); !errors.Is(err, ErrIXMembershipBudget) || got != nil {
		t.Fatal("membership admission exposed a partial prefix", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := snapshot.Members(canceled, 64500, 7, 11, 32<<20, 32<<20); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("membership ignored current cancellation", err)
	}
	expired := en.IXMemberships(at.Add(time.Hour))
	if got, err := expired.Members(t.Context(), 64500, 7, 11, 32<<20, 32<<20); err != nil || got != nil || expired.Current {
		t.Fatal("expired membership remained eligible", err)
	}
	en.mu.Lock()
	en.sources[0].health.Enabled = false
	en.mu.Unlock()
	if en.IXMemberships(time.Now()).Current {
		t.Fatal("disabled membership retained current authority")
	}
	cleared, err := LoadPeeringDBIXMemberships(t.Context(), membershipFile(t, membershipManifest(at, []ixMembershipRecord{})), time.Hour, 1<<20, time.Now())
	if err != nil {
		t.Fatal("explicit complete membership withdrawal was refused", err)
	}
	next := NewEnricher(nil)
	next.Register(cleared)
	withdrawn := next.IXMemberships(time.Now())
	if got, err := withdrawn.Members(t.Context(), 64500, 7, 11, 1<<20, 1<<20); err != nil || len(got) != 0 || !withdrawn.Current || withdrawn.SameGeneration(snapshot) {
		t.Fatal("empty membership replacement revived its former source", err)
	}
}

func TestIXMembershipCacheRefusesPartialCorruptOrUnadmittedWholeManifests(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	row := ixMembershipRecord{ID: 7, IXID: 11, LANID: 13, ASN: 64500, Status: "ok", Operational: true}
	for _, defect := range []string{"incomplete", "count", "future", "null", "unknown", "duplicate", "bad-asn", "bad-status", "bad-ix", "late-row"} {
		t.Run(defect, func(t *testing.T) {
			row := row
			manifest := membershipManifest(at, []ixMembershipRecord{row})
			switch defect {
			case "incomplete":
				manifest["complete"] = false
			case "count":
				manifest["record_count"] = 2
			case "future":
				manifest["observed_at"] = time.Now().Add(time.Hour)
			case "null":
				manifest["data"] = nil
			case "unknown":
				manifest["authority"] = "untrusted"
			case "duplicate":
				manifest["data"], manifest["record_count"] = []ixMembershipRecord{row, row}, 2
			case "bad-asn":
				row.ASN = 0
				manifest["data"] = []ixMembershipRecord{row}
			case "bad-status":
				row.Status = "invented"
				manifest["data"] = []ixMembershipRecord{row}
			case "bad-ix":
				row.IXID = 0
				manifest["data"] = []ixMembershipRecord{row}
			case "late-row":
				bad := row
				bad.ID = 0
				manifest["data"], manifest["record_count"] = []ixMembershipRecord{row, bad}, 2
			}
			if partial, err := LoadPeeringDBIXMemberships(t.Context(), membershipFile(t, manifest), time.Hour, 1<<20, time.Now()); err == nil || partial != nil {
				t.Fatal("partial or invalid membership source became current", defect, err)
			}
		})
	}
	next, last := row, row
	next.ID, last.ID = row.ID+1, row.ID+2
	manifest := membershipManifest(at, []ixMembershipRecord{row, next, last})
	path := membershipFile(t, manifest)
	if partial, err := LoadPeeringDBIXMemberships(t.Context(), path, time.Hour, 4096, time.Now()); !errors.Is(err, ErrIXMembershipBudget) || partial != nil {
		t.Fatal("complete membership source escaped input admission", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if partial, err := LoadPeeringDBIXMemberships(ctx, path, time.Hour, 1<<20, time.Now()); !errors.Is(err, context.Canceled) || partial != nil {
		t.Fatal("membership loader ignored cancellation", err)
	}
}
