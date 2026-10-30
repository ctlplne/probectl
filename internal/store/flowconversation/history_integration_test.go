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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryJournalPostgresOwnerHistoryLookupAndPaging(t *testing.T) {
	admin, pool := journalFixture(t)
	if admin == nil {
		return
	}
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	blue := f
	var err error
	blue.scope.TenantID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	blue.context = tenancy.WithTenant(t.Context(), tenancy.ID(blue.scope.TenantID))
	blue.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, blue.scope.TenantID, blue.scope.OwnerID, blue.credentialID, blue.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{f.scope.TenantID, blue.scope.TenantID} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned history fixture')`, tenant, "probectl-qa-beta-history-"+strings.ReplaceAll(tenant, "-", "")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{f.scope.TenantID, blue.scope.TenantID}); err != nil {
			t.Error("owned history tenant cleanup failed")
		}
	})
	journal := NewJournal(pool)
	meta := inputMetadata()
	meta.FrozenAt = meta.FrozenAt.Truncate(time.Second).Add(987654321 * time.Nanosecond)
	allowInput := func(f messageCodecFixture) AuthorizeMessage {
		return func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
			return f.authorize(ctx, f.scope, origin, required)
		}
	}
	admit := func(f messageCodecFixture, scope MessageScope, m InputMetadata, body string) PreparedInput {
		t.Helper()
		request := f.requestContext(t)
		value, err := f.codec.PrepareInput(request, scope, m, []string{"ai.query", "flow.read", "metrics.read"}, []byte(body), allowInput(f))
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.AdmitInput(request, value, allowInput(f)); err != nil {
			t.Fatal(err)
		}
		return value
	}
	root := admit(f, f.scope, meta, `{"q":"red-1","exact":18446744073709551617}`)
	keys := []Revision{{MessageID: f.scope.MessageID, Revision: 1}}
	for i := 2; i <= 3; i++ {
		scope := f.scope
		scope.MessageID, err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		m := meta
		m.Parent = &keys[0]
		admit(f, scope, m, fmt.Sprintf(`{"q":"red-%d"}`, i))
		keys = append(keys, Revision{MessageID: scope.MessageID, Revision: 1})
	}
	blueContext := blue.requestContext(t)
	admit(blue, blue.scope, meta, `{"q":"blue"}`)
	got, err := journal.Lookup(ctx, f.scope.ConversationID, keys[0], 1<<20, f.authorizeHistory)
	if err != nil || got.Scope() != f.scope || got.Kind() != "input" || !got.Metadata().FrozenAt.Equal(meta.FrozenAt) {
		t.Fatal("exact owner-private lookup failed", err)
	}
	plain, err := f.codec.Open(ctx, got.Scope(), got.Ciphertext(), allowInput(f))
	if err != nil || string(plain) != `{"q":"red-1","exact":18446744073709551617}` {
		t.Fatal("stored source changed through actual SQL lookup", err)
	}
	clear(plain)
	child, err := journal.Lookup(ctx, f.scope.ConversationID, keys[1], 1<<20, f.authorizeHistory)
	if err != nil || child.Metadata().Parent == nil {
		t.Fatal("explicit parent metadata missing", err)
	}
	metadataCopy := child.Metadata()
	metadataCopy.Parent.Revision = 99
	if child.Metadata().Parent.Revision != 1 {
		t.Fatal("metadata accessor mutated immutable stored parent")
	}
	if got, err := journal.Lookup(blueContext, f.scope.ConversationID, keys[1], 1<<20, blue.authorizeHistory); got.value != nil || !errors.Is(err, ErrJournalConflict) {
		t.Fatal("blue read a red-only private message", err)
	}
	blueMessage, err := journal.Lookup(blueContext, blue.scope.ConversationID, keys[0], 1<<20, blue.authorizeHistory)
	if err != nil || blueMessage.Scope().TenantID != blue.scope.TenantID {
		t.Fatal("colliding blue logical ID selected red storage", err)
	}
	plain, err = blue.codec.Open(blueContext, blueMessage.Scope(), blueMessage.Ciphertext(), allowInput(blue))
	if err != nil || string(plain) != `{"q":"blue"}` {
		t.Fatal("colliding tenant ciphertext/source crossed boundary", err)
	}
	clear(plain)
	foreignOwner := f
	foreignOwner.scope.OwnerID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	foreignOwner.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, f.scope.TenantID, foreignOwner.scope.OwnerID, f.credentialID, f.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	foreignContext := foreignOwner.requestContext(t)
	if got, err := journal.Lookup(foreignContext, f.scope.ConversationID, keys[0], 1<<20, foreignOwner.authorizeHistory); got.value != nil || !errors.Is(err, ErrJournalConflict) {
		t.Fatal("same-tenant foreign owner read private lookup", err)
	}
	if page, err := journal.Page(foreignContext, f.scope.ConversationID, nil, HistoryBudget{Rows: 2, Bytes: 1 << 20}, foreignOwner.authorizeHistory); err != nil || len(page.Messages) != 0 || page.Next != nil {
		t.Fatal("same-tenant foreign owner observed private history", err)
	}
	budget := HistoryBudget{Rows: 1, Bytes: 1 << 20}
	first, err := journal.Page(ctx, f.scope.ConversationID, nil, budget, f.authorizeHistory)
	if err != nil || len(first.Messages) != 1 || first.Next == nil || first.Messages[0].Scope().MessageID != keys[0].MessageID {
		t.Fatal("first bounded page failed", err)
	}
	if page, err := journal.Page(blueContext, f.scope.ConversationID, first.Next, budget, blue.authorizeHistory); page.Messages != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("private continuation crossed tenant boundary", err)
	}
	if page, err := journal.Page(foreignContext, f.scope.ConversationID, first.Next, budget, foreignOwner.authorizeHistory); page.Messages != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("private continuation crossed owner boundary", err)
	}
	// Append after the captured first-page bound. It belongs to a new traversal,
	// not to the in-progress history walk.
	laterScope := f.scope
	laterScope.MessageID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	admit(f, laterScope, meta, `{"q":"red-4-later"}`)
	current := first
	seen := []string{first.Messages[0].Scope().MessageID}
	for current.Next != nil {
		current, err = NewJournal(pool).Page(ctx, f.scope.ConversationID, current.Next, budget, f.authorizeHistory)
		if err != nil || len(current.Messages) != 1 || len(seen) > 3 {
			t.Fatal("keyset continuation lost or repeated history", err)
		}
		seen = append(seen, current.Messages[0].Scope().MessageID)
	}
	if len(seen) != 3 || seen[1] != keys[1].MessageID || seen[2] != keys[2].MessageID {
		t.Fatal("concurrent append shifted original upper-bound traversal", seen)
	}
	all, err := journal.Page(ctx, f.scope.ConversationID, nil, HistoryBudget{Rows: 10, Bytes: 1 << 20}, f.authorizeHistory)
	if err != nil || len(all.Messages) != 4 || all.Next != nil || all.Messages[3].Scope().MessageID != laterScope.MessageID {
		t.Fatal("fresh traversal failed to include later publication", err)
	}
	// Paging is current-owner authority, independent of the creator credential.
	fresh := f
	fresh.storedHash, err = crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	fresh.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, f.scope.TenantID, f.scope.OwnerID, f.credentialID, fresh.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	if page, err := journal.Page(fresh.requestContext(t), f.scope.ConversationID, first.Next, budget, fresh.authorizeHistory); err != nil || len(page.Messages) != 1 || page.Messages[0].Scope().MessageID != keys[1].MessageID {
		t.Fatal("fresh same-owner credential could not continue retained history", err)
	}
	calls := 0
	denied := func(ctx context.Context, tenant, owner string, origin auth.WorkerCredentialRef) error {
		calls++
		if calls == 2 {
			return errors.New("current authority revoked after SQL")
		}
		return f.authorizeHistory(ctx, tenant, owner, origin)
	}
	if page, err := journal.Page(ctx, f.scope.ConversationID, nil, budget, denied); page.Messages != nil || page.Next != nil || !errors.Is(err, ErrMessageDenied) || calls != 2 {
		t.Fatal("final current-authority refusal returned private history", err)
	}
	calls = 0
	if message, err := journal.Lookup(ctx, f.scope.ConversationID, keys[0], 1<<20, denied); message.value != nil || !errors.Is(err, ErrMessageDenied) || calls != 2 {
		t.Fatal("final current-authority refusal returned private lookup", err)
	}
	lookupBytes := len(root.input.sealed.parts.header) + len(root.input.sealed.parts.payload)
	if got, err := journal.Lookup(ctx, f.scope.ConversationID, keys[0], lookupBytes, f.authorizeHistory); err != nil || got.value == nil {
		t.Fatal("exact positive lookup byte resource refused", err)
	}
	if got, err := journal.Lookup(ctx, f.scope.ConversationID, keys[0], lookupBytes-1, f.authorizeHistory); got.value != nil || !errors.Is(err, ErrMessageBudget) {
		t.Fatal("lookup byte refusal returned a private record", err)
	}
	if page, err := journal.Page(ctx, f.scope.ConversationID, nil, HistoryBudget{Rows: 2, Bytes: lookupBytes}, f.authorizeHistory); page.Messages != nil || page.Next != nil || !errors.Is(err, ErrMessageBudget) {
		t.Fatal("cumulative byte refusal returned partial history", err)
	}
	// A cursor cannot silently skip data that expires between pages.
	shortScope := f.scope
	shortScope.ConversationID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	shortScope.MessageID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	shortMeta := inputMetadata()
	shortMeta.ExpiresAt = time.Now().Add(2 * time.Second)
	admit(f, shortScope, shortMeta, `{"q":"expires"}`)
	shortScope.MessageID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	admit(f, shortScope, shortMeta, `{"q":"expires-next"}`)
	short, err := journal.Page(ctx, shortScope.ConversationID, nil, budget, f.authorizeHistory)
	if err != nil || short.Next == nil {
		t.Fatal("short-retention continuation fixture unavailable", err)
	}
	for {
		var expired bool
		if err := admin.QueryRow(ctx, `SELECT clock_timestamp()>=$1::timestamptz`, short.Next.window.validUntil).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if page, err := journal.Page(ctx, shortScope.ConversationID, short.Next, budget, f.authorizeHistory); page.Messages != nil || page.Next != nil || !errors.Is(err, ErrJournalConflict) {
		t.Fatal("expired continuation silently skipped retained history", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE flow_conversation_epochs SET generation=generation+1 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if page, err := journal.Page(ctx, f.scope.ConversationID, first.Next, budget, f.authorizeHistory); page.Messages != nil || page.Next != nil || !errors.Is(err, ErrJournalGeneration) {
		t.Fatal("history continuation survived lifecycle generation change", err)
	}
}
