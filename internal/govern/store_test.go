// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// fakeRow is a pgx.Row double for ScanPolicy. It assigns the stored column
// values into the destinations ScanPolicy passes
// (classifications []byte, redact_from string, redact_export bool,
// ai_remote_egress bool), or returns scanErr before any assignment.
type fakeRow struct {
	classes  []byte
	from     string
	redactEx bool
	aiEgress bool
	scanErr  error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	if len(dest) != 4 {
		return errors.New("fakeRow: expected 4 destinations")
	}
	*(dest[0].(*[]byte)) = r.classes
	*(dest[1].(*string)) = r.from
	*(dest[2].(*bool)) = r.redactEx
	*(dest[3].(*bool)) = r.aiEgress
	return nil
}

func TestScanPolicy(t *testing.T) {
	t.Run("no row yields defaults", func(t *testing.T) {
		pol, ok, err := ScanPolicy(fakeRow{scanErr: pgx.ErrNoRows})
		if err != nil || ok {
			t.Fatalf("no-row scan = (%+v, %v, %v), want (zero, false, nil)", pol, ok, err)
		}
		if len(pol.Overrides) != 0 || pol.RedactFrom != ClassUnset {
			t.Fatalf("no-row policy not zero: %+v", pol)
		}
	})

	t.Run("scan error propagates", func(t *testing.T) {
		sentinel := errors.New("boom")
		if _, ok, err := ScanPolicy(fakeRow{scanErr: sentinel}); ok || !errors.Is(err, sentinel) {
			t.Fatalf("scan error = (ok=%v, %v), want (false, boom)", ok, err)
		}
	})

	t.Run("full row parses classes and fields", func(t *testing.T) {
		classes, _ := json.Marshal(map[string]string{"hostname": "confidential", "ip": "pii"})
		pol, ok, err := ScanPolicy(fakeRow{
			classes:  classes,
			from:     "pii",
			redactEx: true,
			aiEgress: true,
		})
		if err != nil || !ok {
			t.Fatalf("full-row scan err=%v ok=%v", err, ok)
		}
		if pol.RedactFrom != ClassPII || !pol.RedactExport || !pol.AIRemoteEgress {
			t.Fatalf("scalar fields wrong: %+v", pol)
		}
		if got := pol.Overrides[Category("hostname")]; got != ClassConfidential {
			t.Fatalf("hostname override = %v, want confidential", got)
		}
		if got := pol.Overrides[Category("ip")]; got != ClassPII {
			t.Fatalf("ip override = %v, want pii", got)
		}
	})

	t.Run("empty classes leaves overrides nil", func(t *testing.T) {
		pol, ok, err := ScanPolicy(fakeRow{classes: []byte(`{}`), from: ""})
		if err != nil || !ok {
			t.Fatalf("empty-classes scan err=%v ok=%v", err, ok)
		}
		if pol.Overrides != nil {
			t.Fatalf("empty classes should leave overrides nil, got %+v", pol.Overrides)
		}
		if pol.RedactFrom != ClassUnset {
			t.Fatalf("empty from should parse to ClassUnset, got %v", pol.RedactFrom)
		}
	})
}

// fakeQuerier records the single Exec UpsertPolicyTx makes. Query/QueryRow are
// unused by that path and fail the test if called.
type fakeQuerier struct {
	t       *testing.T
	sql     string
	args    []any
	execErr error
	calls   int
}

func (q *fakeQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	q.calls++
	q.sql = sql
	q.args = args
	return pgconn.CommandTag{}, q.execErr
}

func (q *fakeQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	q.t.Fatal("UpsertPolicyTx must not call Query")
	return nil, nil
}

func (q *fakeQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	q.t.Fatal("UpsertPolicyTx must not call QueryRow")
	return nil
}

var _ tenancy.Querier = (*fakeQuerier)(nil)

func TestUpsertPolicyTx(t *testing.T) {
	t.Run("marshals overrides and scalar fields into the upsert args", func(t *testing.T) {
		q := &fakeQuerier{t: t}
		pol := Policy{
			Overrides:      map[Category]Class{Category("hostname"): ClassConfidential},
			RedactFrom:     ClassPII,
			RedactExport:   true,
			AIRemoteEgress: true,
		}
		if err := UpsertPolicyTx(context.Background(), q, "tenant-a", pol, "admin@tenant"); err != nil {
			t.Fatalf("UpsertPolicyTx: %v", err)
		}
		if q.calls != 1 {
			t.Fatalf("Exec called %d times, want 1", q.calls)
		}
		if len(q.args) != 7 {
			t.Fatalf("Exec got %d args, want 7: %#v", len(q.args), q.args)
		}
		if q.args[0] != "tenant-a" {
			t.Errorf("tenant_id arg = %v, want tenant-a (the caller scope, never a body value)", q.args[0])
		}
		var classes map[string]string
		if err := json.Unmarshal([]byte(q.args[1].(string)), &classes); err != nil {
			t.Fatalf("classifications arg is not JSON: %v", err)
		}
		if classes["hostname"] != "confidential" {
			t.Errorf("classifications = %v, want hostname=confidential", classes)
		}
		if q.args[2] != "pii" {
			t.Errorf("redact_from arg = %v, want pii", q.args[2])
		}
		if q.args[3] != true || q.args[4] != true {
			t.Errorf("redact_export/ai_remote_egress = %v/%v, want true/true", q.args[3], q.args[4])
		}
		if q.args[6] != "admin@tenant" {
			t.Errorf("updated_by arg = %v, want admin@tenant", q.args[6])
		}
	})

	t.Run("unset RedactFrom writes an empty redact_from", func(t *testing.T) {
		q := &fakeQuerier{t: t}
		if err := UpsertPolicyTx(context.Background(), q, "tenant-b", Policy{}, "by"); err != nil {
			t.Fatalf("UpsertPolicyTx: %v", err)
		}
		if q.args[2] != "" {
			t.Errorf("redact_from for ClassUnset = %q, want empty", q.args[2])
		}
	})

	t.Run("exec error propagates", func(t *testing.T) {
		sentinel := errors.New("exec failed")
		q := &fakeQuerier{t: t, execErr: sentinel}
		if err := UpsertPolicyTx(context.Background(), q, "tenant-c", Policy{}, "by"); !errors.Is(err, sentinel) {
			t.Fatalf("UpsertPolicyTx error = %v, want exec failed", err)
		}
	})
}

func TestNewPolicyStore(t *testing.T) {
	if NewPolicyStore(nil) == nil {
		t.Fatal("NewPolicyStore returned nil")
	}
}

func TestSetTenantPolicyRequiresAuditReceipt(t *testing.T) {
	// A governance/consent change must never persist unaudited (G7-7): a nil
	// audit-receipt callback fails closed before any store work, so this needs
	// no database.
	s := NewPolicyStore(nil)
	err := s.SetTenantPolicy(context.Background(), "tenant-a", Policy{}, "admin", nil)
	if !errors.Is(err, ErrAuditReceiptRequired) {
		t.Fatalf("SetTenantPolicy(nil auditTx) = %v, want ErrAuditReceiptRequired", err)
	}
}
