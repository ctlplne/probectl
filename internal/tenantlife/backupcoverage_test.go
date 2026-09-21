// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/flowstore"
)

// COMPLY-002: with a stated backup retention, the attestation quantifies a
// BOUNDED window — erased_at + retention — by which every backup containing
// the tenant has aged out, so erasure provably covers backups (not just the
// live stores). The deadline is part of the hashed, audit-grade report.
func TestErasureAttestationCoversBackupsBoundedWindow(t *testing.T) {
	ctx := context.Background()
	flows := flowstore.NewMemory()
	_ = flows.Insert(ctx, []flowstore.Row{{TenantID: "victim", AgentID: "a", Exporter: "e",
		TS: time.Now(), SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", Bytes: 1, Packets: 1}})

	fixed := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	e := NewWithBackupRetention(nil, flows, nil, nil, nil,
		"backups expire 30 days after they are taken", 30, nil).
		WithClock(func() time.Time { return fixed })

	att, err := e.Erase(ctx, "victim", "victim-slug", "compliance-officer")
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if att.BackupRetentionDays != 30 {
		t.Fatalf("retention window not recorded: %d", att.BackupRetentionDays)
	}
	if att.BackupErasureDeadline == nil {
		t.Fatal("a quantified retention must yield a concrete backup-erasure deadline")
	}
	want := fixed.Add(30 * 24 * time.Hour)
	if !att.BackupErasureDeadline.Equal(want) {
		t.Fatalf("deadline = %s, want erased_at + 30d = %s", att.BackupErasureDeadline, want)
	}
	// The bounded window is part of the tamper-evident report (in the hash).
	if att.ReportSHA256 == "" {
		t.Fatal("attestation must be hashed")
	}
	b, _ := json.Marshal(att)
	if !contains(b, "backup_erasure_deadline") || !contains(b, "backup_retention_days") {
		t.Fatalf("attestation JSON must surface the backup-coverage window:\n%s", b)
	}

	// Re-hashing without the deadline field would change the digest — proves
	// the deadline is bound into the attestation, not cosmetic.
	cp := att
	cp.BackupErasureDeadline = nil
	cp.BackupRetentionDays = 0
	if cp.hash() == att.ReportSHA256 {
		t.Fatal("the backup-coverage window must be covered by the report hash")
	}
}

// Without a stated retention, the attestation is honest: the note records the
// operator's policy, but no fabricated deadline is asserted.
func TestErasureAttestationNoteOnlyWhenUnquantified(t *testing.T) {
	ctx := context.Background()
	e := New(nil, flowstore.NewMemory(), nil, nil, nil, "note-only policy", nil).
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	att, err := e.Erase(ctx, "t", "slug", "actor")
	if err != nil {
		t.Fatal(err)
	}
	if att.BackupErasureDeadline != nil || att.BackupRetentionDays != 0 {
		t.Fatalf("unquantified retention must NOT assert a deadline: %+v", att)
	}
	if att.BackupPolicy != "note-only policy" {
		t.Fatalf("the operator's note must still be recorded: %q", att.BackupPolicy)
	}
}

func contains(b []byte, s string) bool {
	return len(b) > 0 && indexOf(string(b), s) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
