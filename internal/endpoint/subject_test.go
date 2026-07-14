// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSnapshotStoreSubjectLifecycleIsTenantScoped(t *testing.T) {
	s := NewSnapshotStore(0)
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	s.Record("tenant-a", "alice-laptop", rv(TypeWiFi, "CorpNet", at, nil, map[string]string{"owner": "alice@example.com"}))
	s.Record("tenant-a", "shared-laptop", rv(TypeSession, "alice.service.example", at.Add(time.Second), nil, nil))
	s.Record("tenant-a", "shared-laptop", rv(TypeGateway, "192.0.2.1", at.Add(2*time.Second), nil, map[string]string{"owner": "bob@example.com"}))
	s.Record("tenant-b", "alice-secret", rv(TypeWiFi, "SecretNet", at, nil, map[string]string{"owner": "alice@example.com"}))

	for _, tc := range []struct {
		tenant  string
		subject string
	}{
		{tenant: "", subject: "alice"},
		{tenant: "tenant-a", subject: " "},
	} {
		var out bytes.Buffer
		if rows, err := s.ExportSubject(tc.tenant, tc.subject, &out); err != nil || rows != 0 || out.Len() != 0 {
			t.Fatalf("ExportSubject(%q, %q) = rows=%d bytes=%d err=%v, want empty", tc.tenant, tc.subject, rows, out.Len(), err)
		}
	}

	var out bytes.Buffer
	rows, err := s.ExportSubject("tenant-a", " ALICE ", &out)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("export rows = %d, want endpoint-id + session matches", rows)
	}
	body := out.String()
	if !strings.Contains(body, "alice-laptop") || !strings.Contains(body, "alice.service.example") {
		t.Fatalf("export omitted tenant-a matches: %s", body)
	}
	if strings.Contains(body, "alice-secret") || strings.Contains(body, "SecretNet") {
		t.Fatalf("CROSS-TENANT LEAK in subject export: %s", body)
	}

	if rows, err := s.ExportSubject("tenant-a", "alice", failingWriter{}); !errors.Is(err, errSubjectWriter) || rows != 0 {
		t.Fatalf("failed export = rows=%d err=%v, want zero + writer error", rows, err)
	}

	deleted, remaining := s.DeleteSubject("tenant-a", "alice")
	if deleted != 2 || remaining != 0 {
		t.Fatalf("DeleteSubject = deleted=%d remaining=%d, want 2/0", deleted, remaining)
	}
	views := s.List("tenant-a")
	if len(views) != 1 || views[0].AgentID != "shared-laptop" || views[0].Gateway == nil || len(views[0].Sessions) != 0 {
		t.Fatalf("tenant-a post-delete views = %+v", views)
	}
	if got := s.List("tenant-b"); len(got) != 1 || got[0].AgentID != "alice-secret" {
		t.Fatalf("tenant-b changed by tenant-a delete: %+v", got)
	}
	if deleted, remaining := s.DeleteSubject("", "alice"); deleted != 0 || remaining != 0 {
		t.Fatalf("unscoped delete = %d/%d, want fail-closed zero", deleted, remaining)
	}
}

var errSubjectWriter = errors.New("subject writer failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errSubjectWriter }
