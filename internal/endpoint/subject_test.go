// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestSnapshotStoreSubjectLifecycleIsTenantScoped exercises EXACT, field-typed
// subject matching (TEN-05). The subject "alice@example.com" matches a row only
// when an endpoint target or attribute VALUE is exactly that string — not when a
// value merely contains it ("alice@example.com.evil") and not a different agent
// id ("alice-laptop" is matched through its owner attribute, not by substring).
func TestSnapshotStoreSubjectLifecycleIsTenantScoped(t *testing.T) {
	const subject = "alice@example.com"
	s := NewSnapshotStore(0)
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	s.Record("tenant-a", "alice-laptop", rv(TypeWiFi, "CorpNet", at, nil, map[string]string{"owner": subject}))
	s.Record("tenant-a", "shared-laptop", rv(TypeSession, subject, at.Add(time.Second), nil, nil))
	s.Record("tenant-a", "shared-laptop", rv(TypeGateway, "192.0.2.1", at.Add(2*time.Second), nil, map[string]string{"owner": "bob@example.com"}))
	// Over-match guard: a longer value that CONTAINS the subject must not match.
	s.Record("tenant-a", "decoy-laptop", rv(TypeWiFi, "CorpNet", at, nil, map[string]string{"owner": subject + ".evil"}))
	s.Record("tenant-b", "alice-secret", rv(TypeWiFi, "SecretNet", at, nil, map[string]string{"owner": subject}))

	for _, tc := range []struct {
		tenant  string
		subject string
	}{
		{tenant: "", subject: subject},
		{tenant: "tenant-a", subject: " "},
	} {
		var out bytes.Buffer
		if rows, err := s.ExportSubject(tc.tenant, tc.subject, &out); err != nil || rows != 0 || out.Len() != 0 {
			t.Fatalf("ExportSubject(%q, %q) = rows=%d bytes=%d err=%v, want empty", tc.tenant, tc.subject, rows, out.Len(), err)
		}
	}

	var out bytes.Buffer
	rows, err := s.ExportSubject("tenant-a", " "+strings.ToUpper(subject)+" ", &out)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("export rows = %d, want the owner-attr WiFi + the session target (exact)", rows)
	}
	body := out.String()
	if !strings.Contains(body, "alice-laptop") || !strings.Contains(body, "shared-laptop") {
		t.Fatalf("export omitted tenant-a exact matches: %s", body)
	}
	if strings.Contains(body, "alice-secret") || strings.Contains(body, "SecretNet") {
		t.Fatalf("CROSS-TENANT LEAK in subject export: %s", body)
	}
	if strings.Contains(body, "decoy-laptop") || strings.Contains(body, ".evil") {
		t.Fatalf("OVER-MATCH: a value containing the subject was exported: %s", body)
	}

	if rows, err := s.ExportSubject("tenant-a", subject, failingWriter{}); !errors.Is(err, errSubjectWriter) || rows != 0 {
		t.Fatalf("failed export = rows=%d err=%v, want zero + writer error", rows, err)
	}

	deleted, remaining := s.DeleteSubject("tenant-a", subject)
	if deleted != 2 || remaining != 0 {
		t.Fatalf("DeleteSubject = deleted=%d remaining=%d, want 2/0", deleted, remaining)
	}
	views := s.List("tenant-a")
	byAgent := map[string]View{}
	for _, v := range views {
		byAgent[v.AgentID] = v
	}
	if _, gone := byAgent["alice-laptop"]; gone {
		t.Fatalf("subject-owned endpoint survived delete: %+v", views)
	}
	if shared, ok := byAgent["shared-laptop"]; !ok || shared.Gateway == nil || len(shared.Sessions) != 0 {
		t.Fatalf("tenant-a shared-laptop post-delete = %+v (want gateway kept, session erased)", views)
	}
	if _, ok := byAgent["decoy-laptop"]; !ok {
		t.Fatalf("OVER-MATCH: the containing-but-not-exact decoy row was erased: %+v", views)
	}
	if got := s.List("tenant-b"); len(got) != 1 || got[0].AgentID != "alice-secret" {
		t.Fatalf("tenant-b changed by tenant-a delete: %+v", got)
	}
	if deleted, remaining := s.DeleteSubject("", subject); deleted != 0 || remaining != 0 {
		t.Fatalf("unscoped delete = %d/%d, want fail-closed zero", deleted, remaining)
	}
}

var errSubjectWriter = errors.New("subject writer failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errSubjectWriter }
