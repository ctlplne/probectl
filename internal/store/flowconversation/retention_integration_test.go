// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowconversation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
)

func TestHistoryJournalPostgresPolicyDeadlinesAndParentBounds(t *testing.T) {
	admin, pool := journalFixture(t)
	if admin == nil {
		return
	}
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned deadline fixture')`, f.scope.TenantID, "probectl-qa-beta-deadline-"+strings.ReplaceAll(f.scope.TenantID, "-", "")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DELETE FROM tenants WHERE id=$1::uuid`, f.scope.TenantID); err != nil {
			t.Error("owned deadline tenant cleanup failed")
		}
	})
	journal := NewJournal(pool)
	allow := func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
		return f.authorize(ctx, f.scope, origin, required)
	}
	meta := inputMetadata()
	meta.ExpiresAt = time.Time{}
	prepare := func(scope MessageScope, m InputMetadata) PreparedInput {
		t.Helper()
		prepared, err := f.codec.PrepareInput(ctx, scope, m, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"q":"policy-derived deadline"}`), allow)
		if err != nil {
			t.Fatal(err)
		}
		return prepared
	}
	root := prepare(f.scope, meta)
	if err := journal.AdmitInput(ctx, root, allow); err != nil {
		t.Fatal("unlimited policy input admission refused", err)
	}
	childScope := f.scope
	var err error
	childScope.MessageID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	childMeta := meta
	childMeta.Parent = &Revision{MessageID: f.scope.MessageID, Revision: 1}
	if err := journal.AdmitInput(ctx, prepare(childScope, childMeta), allow); err != nil {
		t.Fatal("unlimited parent/child policy refused", err)
	}
	first, err := journal.Page(ctx, f.scope.ConversationID, nil, HistoryBudget{Rows: 1, Bytes: 1 << 20}, f.authorizeHistory)
	if err != nil || len(first.Messages) != 1 || first.Next == nil || !first.Messages[0].Metadata().ExpiresAt.IsZero() || !first.Next.window.validUntil.IsZero() {
		t.Fatal("unlimited history received a fabricated deadline or missing page", err)
	}
	second, err := NewJournal(pool).Page(ctx, f.scope.ConversationID, first.Next, HistoryBudget{Rows: 1, Bytes: 1 << 20}, f.authorizeHistory)
	if err != nil || len(second.Messages) != 1 || second.Next != nil || !second.Messages[0].Metadata().ExpiresAt.IsZero() {
		t.Fatal("unlimited history continuation failed", err)
	}
	stored, err := journal.Lookup(ctx, f.scope.ConversationID, Revision{MessageID: childScope.MessageID, Revision: 1}, 1<<20, f.authorizeHistory)
	if err != nil || !stored.Metadata().ExpiresAt.IsZero() {
		t.Fatal("unlimited same-owner lookup failed", err)
	}
	var nullDeadlines int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND expires_at IS NULL`, f.scope.TenantID).Scan(&nullDeadlines); err != nil || nullDeadlines != 2 {
		t.Fatal("no-deadline policy was not stored as NULL", nullDeadlines, err)
	}
	finiteScope := f.scope
	finiteScope.ConversationID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	finiteScope.MessageID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	finiteMeta := meta
	finiteMeta.ExpiresAt = meta.FrozenAt.Add(time.Hour)
	if err := journal.AdmitInput(ctx, prepare(finiteScope, finiteMeta), allow); err != nil {
		t.Fatal(err)
	}
	for _, deadline := range []time.Time{{}, finiteMeta.ExpiresAt.Add(time.Minute), finiteMeta.ExpiresAt.Add(-time.Minute)} {
		scope := finiteScope
		scope.MessageID, err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		m := finiteMeta
		m.ExpiresAt, m.Parent = deadline, &Revision{MessageID: finiteScope.MessageID, Revision: 1}
		err = journal.AdmitInput(ctx, prepare(scope, m), allow)
		if deadline.IsZero() || deadline.After(finiteMeta.ExpiresAt) {
			if !errors.Is(err, ErrJournalConflict) {
				t.Fatal("child retained context beyond finite parent deadline", err)
			}
		} else if err != nil {
			t.Fatal("shorter authorized child deadline refused", err)
		}
	}
}
