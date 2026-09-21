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

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/support"
)

// DPR-200: measured on the lab with the audit WORM volume at 100% and zero bytes
// free — /readyz answered 200, an audited mutation returned 201 in under a
// second, the audit trail read fine, and /v1/diagnostics reported `overall: ok`
// across six checks, none of them about the audit export. The exporter was
// already counting its failures and its last success; nothing turned either into
// something an operator could see.
//
// The request path staying up is CORRECT and this test asserts that too: an
// audit row reaches Postgres immediately and the export is asynchronous, so the
// check is on /v1/diagnostics and not on /readyz.
func TestAuditWORMCheckSaysWhatTheVolumeIsDoing(t *testing.T) {
	const dir = "/var/lib/probectl/audit-worm"
	find := func(h support.Health, name string) (support.Check, bool) {
		for _, c := range h.Checks {
			if c.Name == name {
				return c, true
			}
		}
		return support.Check{}, false
	}
	run := func(st audit.WormExportStatus) support.Check {
		t.Helper()
		s := &Server{auditWORMDir: dir, auditWORMStatus: func() audit.WormExportStatus { return st }}
		got, ok := find(s.deepHealth(context.Background()), "audit_worm")
		if !ok {
			t.Fatal("no audit_worm check — a full WORM volume is invisible again")
		}
		return got
	}

	t.Run("a healthy export says when it last succeeded", func(t *testing.T) {
		at := time.Date(2026, 9, 18, 23, 0, 0, 0, time.UTC)
		got := run(audit.WormExportStatus{LastSuccess: at})
		if got.Status != support.StatusOK {
			t.Errorf("status = %v, want ok", got.Status)
		}
		if !strings.Contains(got.Detail, "2026-09-18T23:00:00Z") {
			t.Errorf("the detail must name the time: %q", got.Detail)
		}
	})

	t.Run("an export that cannot write is degraded and names the volume", func(t *testing.T) {
		got := run(audit.WormExportStatus{ExportFailures: 3})
		if got.Status != support.StatusDegraded {
			t.Fatalf("status = %v, want degraded — this is the state the lab was in", got.Status)
		}
		if !strings.Contains(got.Detail, "3 time(s)") {
			t.Errorf("the detail must carry the count: %q", got.Detail)
		}
		if got.Finding == nil {
			t.Fatal("a degraded check must carry a finding an operator can act on")
		}
		body := got.Finding.Evidence + got.Finding.Summary
		if !strings.Contains(body, dir) {
			t.Errorf("the finding must name the volume to look at: %q", body)
		}
		// The two things an operator most needs to know, in this order.
		if !strings.Contains(body, "nothing is lost") {
			t.Errorf("it must say the events are still recorded, or this reads as data loss: %q", body)
		}
		if !strings.Contains(strings.ToLower(body), "free space") {
			t.Errorf("it must name the usual cause: %q", body)
		}
		if !strings.Contains(got.Detail, "never (no cycle has completed)") {
			t.Errorf("a deployment that never exported must say so, not imply a recent success: %q", got.Detail)
		}
	})

	t.Run("a chain failure outranks a write failure and says not to restart", func(t *testing.T) {
		got := run(audit.WormExportStatus{ExportFailures: 2, ChainFailures: 1})
		if got.Status != support.StatusDegraded {
			t.Fatalf("status = %v, want degraded", got.Status)
		}
		if !strings.Contains(got.Detail, "verification") {
			t.Errorf("verification failure must win over a write failure: %q", got.Detail)
		}
		if got.Finding == nil {
			t.Fatal("a chain failure must carry a finding")
		}
		if !strings.Contains(got.Finding.Evidence, "purge or tampering") {
			t.Errorf("the finding must name what this looks like: %q", got.Finding.Evidence)
		}
		if !strings.Contains(got.Finding.Evidence, "not something to clear by restarting") {
			t.Errorf("an operator's first instinct is a restart; the finding must head it off: %q", got.Finding.Evidence)
		}
	})

	t.Run("catching up is not degraded", func(t *testing.T) {
		got := run(audit.WormExportStatus{LastSuccess: time.Now().Add(-time.Minute), Lagging: true})
		if got.Status != support.StatusOK {
			t.Errorf("a lagging-but-writing export is not a fault: %v %q", got.Status, got.Detail)
		}
	})

	t.Run("a deployment without WORM export grows no check", func(t *testing.T) {
		s := &Server{}
		if _, ok := find(s.deepHealth(context.Background()), "audit_worm"); ok {
			t.Error("WORM export is a deployment choice; its absence must not be permanently unhappy")
		}
	})
}
