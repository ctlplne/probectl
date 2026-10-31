// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryJournalPostgresSubjectApplicationBorrowAndApproval(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedSubjectOperation(t, f.journal, f.red, time.Time{})
	seedSubjectOperation(t, f.journal, f.blue, time.Time{})
	ctx := f.operational(t, f.red.scope.TenantID)
	plan, err := f.red.codec.PrepareSubjectErasurePlan(ctx, mustInvalidationUUID(t), "subject@example.test", []string{f.red.scope.OwnerID}, []byte(`{"version":1,"fixture":"approved private application"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Release()
	validated := 0
	pending, err := f.journal.BeginSubjectInvalidation(ctx, f.red.codec, plan, allowActivityMaintenance, func(ctx context.Context, sc tenancy.Scope) error {
		validated++
		var same bool
		if err := sc.Q.QueryRow(ctx, `SELECT current_setting('probectl.tenant_id')=$1`, f.red.scope.TenantID).Scan(&same); err != nil {
			return err
		}
		if !same {
			t.Error("application validation changed tenant")
		}
		return nil
	})
	if err != nil || validated != 1 {
		t.Fatal("application approval was not in the marker transaction", err)
	}
	var frozen SubjectErasurePlan
	var app []byte
	err = f.journal.withSubjectMatchSource(ctx, f.red.codec, pending, allowActivityMaintenance, func(ctx context.Context, borrowed SubjectErasurePlan) error {
		frozen = borrowed
		borrowed.Release() // this callback does not own its active selector
		if err := borrowed.VisitSelector(ctx, func(subject string, aliases []string, body []byte) error {
			app = body
			if subject != "subject@example.test" || len(aliases) == 0 || !bytes.Contains(body, []byte("approved private application")) {
				t.Error("callback release destroyed the immutable approved selector")
			}
			clear(aliases)
			return nil
		}); err != nil {
			return err
		}
		return visitSubjectOperationFixture(ctx, f.journal, f.red, func(_ context.Context, body []byte) error {
			if !bytes.Contains(body, []byte("subject@example.test")) {
				t.Error("application source fixture was not actually opened")
			}
			return nil
		})
	})
	if err != nil || f.active(t, f.red.scope.TenantID) != 0 || !bytes.Equal(app, make([]byte, len(app))) || frozen.value.wire.Subject != "" || frozen.value.wire.Application != nil {
		t.Fatal("borrowed application/source did not clear after actual drain", err)
	}
}
