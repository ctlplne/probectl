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
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func seedExportMessage(t *testing.T, journal *Journal, fixture messageCodecFixture, question string) messageCodecFixture {
	t.Helper()
	fixture.scope.MessageID = mustInvalidationUUID(t)
	return seedExportMetadata(t, journal, fixture, question, inputMetadata())
}

func seedExportMetadata(t *testing.T, journal *Journal, fixture messageCodecFixture, question string, meta InputMetadata) messageCodecFixture {
	t.Helper()
	body, err := json.Marshal(map[string]any{"question": question, "exact": json.RawMessage("18446744073709551617")})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	prepared, err := fixture.codec.PrepareInput(fixture.requestContext(t), fixture.scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, body, fixture.authorize)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.AdmitInput(fixture.requestContext(t), prepared, fixture.authorize); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func exportRecordAuthority(ctx context.Context, scope MessageScope, _ InputMetadata) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != scope.TenantID || auth.PrincipalFrom(ctx) != nil {
		return ErrMessageDenied
	}
	return ctx.Err()
}

func TestHistoryJournalPostgresTenantExportAcrossOwners(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	red := seedExportMessage(t, f.journal, f.red, "owned red one")
	seedExportMessage(t, f.journal, f.red, "owned red two")
	other := f.red
	other.scope.OwnerID = mustInvalidationUUID(t)
	var err error
	other.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, other.scope.TenantID, other.scope.OwnerID, other.credentialID, other.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	seedExportMessage(t, f.journal, other, "owned second owner")
	seedExportMessage(t, f.journal, f.blue, "foreign blue source")
	var out bytes.Buffer
	var escaped func(io.Writer) (int64, error)
	operational := f.operational(t, f.red.scope.TenantID)
	installed, err := f.journal.WithTenantExport(operational, HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, exportRecordAuthority, func(ctx context.Context, stream func(io.Writer) (int64, error)) error {
		if auth.PrincipalFrom(ctx) != nil || f.active(t, f.red.scope.TenantID) != 1 {
			t.Error("independent export borrowed a creator or entered before registration")
		}
		escaped = stream
		count, err := stream(&out)
		if err != nil || count != 3 {
			t.Errorf("complete multi-owner export: count=%d err=%v", count, err)
		}
		return err
	})
	if err != nil || !installed || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("counted export did not acknowledge its actual drain", err)
	}
	decoder := json.NewDecoder(&out)
	owners, count := map[string]bool{}, 0
	for decoder.More() {
		var value portableHistoryMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		if value.TenantID != f.red.scope.TenantID || !bytes.Contains(value.Document, []byte("18446744073709551617")) || bytes.Contains(value.Document, []byte("foreign blue")) {
			t.Fatal("portable history lost tenant scope or exact document data")
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"private_header", "private_payload", "dv1:", f.red.key, f.red.credentialID} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatal("private key/origin/control storage leaked into portability")
			}
		}
		owners[value.OwnerID] = true
		count++
	}
	if count != 3 || len(owners) != 2 {
		t.Fatal("export silently omitted another owner or page", count, len(owners))
	}
	if _, err := escaped(io.Discard); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("escaped export function revived a completed source lease", err)
	}
	// Ordinary owner history must still refuse another owner and a lifecycle
	// request cannot select the independent export path with its Principal.
	if _, err := f.journal.WithTenantExport(red.requestContext(t), HistoryBudget{Rows: 1, Bytes: 1000}, allowActivityMaintenance, exportRecordAuthority, func(context.Context, func(io.Writer) (int64, error)) error { return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("ordinary owner request selected cross-owner privacy maintenance", err)
	}
}

func TestHistoryJournalPostgresTenantExportMandatoryAuditAndCompleteConsumption(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedExportMessage(t, f.journal, f.red, "owned private source")
	ctx := f.operational(t, f.red.scope.TenantID)
	budget := HistoryBudget{Rows: 1, Bytes: 1 << 20}
	restore := activityAuditFault(t, f.admin, "audit_events", f.red.scope.TenantID, "flow.conversation.export_started")
	entered := false
	if _, err := f.journal.WithTenantExport(ctx, budget, allowActivityMaintenance, exportRecordAuthority, func(context.Context, func(io.Writer) (int64, error)) error { entered = true; return nil }); !errors.Is(err, ErrJournalUnavailable) || entered || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("source export entered without its committed audit registration", err)
	}
	restore()
	if _, err := f.journal.WithTenantExport(ctx, budget, allowActivityMaintenance, exportRecordAuthority, func(context.Context, func(io.Writer) (int64, error)) error { return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("export callback reported success without consuming retained history", err)
	}
	if _, err := f.journal.WithTenantExport(ctx, HistoryBudget{Rows: 1, Bytes: 1}, allowActivityMaintenance, exportRecordAuthority, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		_, _ = stream(io.Discard) // A caller cannot hide an incomplete scan.
		return nil
	}); !errors.Is(err, ErrMessageBudget) {
		t.Fatal("ignored streaming resource refusal became a successful export", err)
	}
	restore = activityAuditFault(t, f.admin, "audit_events", f.red.scope.TenantID)
	if _, err := f.journal.WithTenantExport(ctx, budget, allowActivityMaintenance, exportRecordAuthority, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		_, err := stream(io.Discard)
		return err
	}); !errors.Is(err, ErrJournalUnavailable) || f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("failed actual-drain audit disappeared or reported export success", err)
	}
	restore()
	if retried, err := f.journal.RetryDrainedOperations(ctx, ActivityBudget{Rows: 1, TimeLimit: time.Second}, allowActivityMaintenance); err != nil || retried.Acknowledged != 1 || retried.Pending != 0 {
		t.Fatal("known drained export could not retry its source-free acknowledgement", err)
	}
}

type heldExportWriter struct {
	ctx                        context.Context
	started, canceled, release chan struct{}
	once                       sync.Once
}

func (w *heldExportWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.started)
		<-w.ctx.Done()
		close(w.canceled)
		<-w.release
	})
	return len(p), nil
}

func TestHistoryJournalPostgresTenantExportLostLeaseStillRequiresActualWriterDrain(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	seedExportMessage(t, f.journal, f.red, "owned held export buffer")
	operational := f.operational(t, f.red.scope.TenantID)
	writer := &heldExportWriter{started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(writer.release) })
	var allowed atomic.Bool
	allowed.Store(true)
	check := func(ctx context.Context, tenant string) error {
		if !allowed.Load() {
			return ErrMessageDenied
		}
		return allowActivityMaintenance(ctx, tenant)
	}
	finished := make(chan error, 1)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		_, err := f.journal.WithTenantExport(operational, HistoryBudget{Rows: 1, Bytes: 1 << 20}, check, exportRecordAuthority, func(ctx context.Context, stream func(io.Writer) (int64, error)) error {
			writer.ctx = ctx
			_, err := stream(writer)
			return err
		})
		finished <- err
	}()
	t.Cleanup(func() {
		allowed.Store(false)
		release()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("owned export writer did not drain")
		}
	})
	select {
	case <-writer.started:
	case err := <-finished:
		t.Fatal("actual export source never reached its writer", err)
	case <-time.After(5 * time.Second):
		t.Fatal("export writer start timed out")
	}
	allowed.Store(false)
	select {
	case <-writer.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("live authority loss did not cancel actual export IO")
	}
	if f.active(t, f.red.scope.TenantID) != 1 {
		t.Fatal("cancellation acknowledged a still-running export writer")
	}
	pending, err := f.journal.BeginInvalidation(operational, maintenanceRequestFixture(f.red), allowActivityMaintenance)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := f.admin.QueryRow(t.Context(), `WITH lease_key AS(SELECT hashtextextended('probectl.flow_conversations.operation:'||$1::text,0) AS value)
 SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid,lease_key WHERE l.locktype='advisory' AND l.granted AND l.mode='ShareLock' AND l.objsubid=1 AND l.classid=((lease_key.value>>32)&4294967295)::oid AND l.objid=(lease_key.value&4294967295)::oid AND a.datname=current_database() AND a.query LIKE '%probectl.flow_conversations.operation:%'`, f.red.scope.TenantID).Scan(&pid); err != nil {
		t.Fatal("owned export lease backend was not positively observed", err)
	}
	var killed bool
	if err := f.admin.QueryRow(t.Context(), `SELECT pg_terminate_backend($1)`, pid).Scan(&killed); err != nil || !killed {
		t.Fatal("owned export lease fault failed", err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), f.pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	replica := NewJournal(pool)
	entered := false
	if err := replica.WithDrainedInvalidation(operational, pending, allowActivityMaintenance, func(context.Context) error { entered = true; return nil }); !errors.Is(err, ErrJournalDraining) || entered {
		t.Fatal("lost SQL lease certified a live export buffer as drained", err)
	}
	if _, err := replica.WithTenantExport(f.operational(t, f.blue.scope.TenantID), HistoryBudget{Rows: 1, Bytes: 1000}, allowActivityMaintenance, exportRecordAuthority, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		_, err := stream(io.Discard)
		return err
	}); err != nil {
		t.Fatal("red export drain blocked independent blue portability", err)
	}
	release()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("revoked export returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("released owned export failed to return")
	}
	if f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("actual export writer drain did not commit its acknowledgement")
	}
	if err := replica.WithDrainedInvalidation(operational, pending, allowActivityMaintenance, func(context.Context) error { entered = true; return nil }); err != nil || !entered {
		t.Fatal("actual export drain left a false pending source", err)
	}
}

func TestHistoryJournalPostgresSubjectExportCompleteDescendantClosure(t *testing.T) {
	f := newActivityFixture(t)
	if f.admin == nil {
		return
	}
	meta := inputMetadata()
	add := func(id, question string, parent *Revision) messageCodecFixture {
		t.Helper()
		fixture := f.red
		fixture.scope.MessageID = id
		m := meta
		m.Parent = parent
		return seedExportMetadata(t, f.journal, fixture, question, m)
	}
	unrelated := add("00000000-0000-4000-8000-000000000010", "unrelated leading page", nil)
	root := add("00000000-0000-4000-8000-000000000020", "MATCH_SUBJECT in root", nil)
	parent := Revision{MessageID: root.scope.MessageID, Revision: 1}
	child := add("00000000-0000-4000-8000-000000000030", "child inherited context without literal", &parent)
	parent = Revision{MessageID: child.scope.MessageID, Revision: 1}
	add("00000000-0000-4000-8000-000000000040", "grandchild inherited context without literal", &parent)
	parent = Revision{MessageID: unrelated.scope.MessageID, Revision: 1}
	add("00000000-0000-4000-8000-000000000050", "nonmatching sibling branch", &parent)
	seedExportMessage(t, f.journal, f.blue, "MATCH_SUBJECT foreign blue")
	matcher := func(ctx context.Context, record StoredMessage, body []byte) (bool, error) {
		scope := record.Scope()
		if auth.PrincipalFrom(ctx) != nil || scope.TenantID != f.red.scope.TenantID {
			return false, ErrMessageDenied
		}
		return bytes.Contains(body, []byte("MATCH_SUBJECT")), ctx.Err()
	}
	var out bytes.Buffer
	installed, err := f.journal.WithSubjectExport(f.operational(t, f.red.scope.TenantID), HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, exportRecordAuthority, matcher, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		count, err := stream(&out)
		if count != 3 || err != nil {
			t.Errorf("subject closure omitted a later page or descendant:count=%d err=%v", count, err)
		}
		return err
	})
	if !installed || err != nil || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("subject export failed or retired incorrectly", err)
	}
	var ids []string
	decoder := json.NewDecoder(&out)
	for decoder.More() {
		var message portableHistoryMessage
		if err := decoder.Decode(&message); err != nil {
			t.Fatal(err)
		}
		if message.TenantID != f.red.scope.TenantID || bytes.Contains(message.Document, []byte("foreign blue")) {
			t.Fatal("subject selector crossed tenant boundary")
		}
		ids = append(ids, message.MessageID)
	}
	if len(ids) != 3 || ids[0] != root.scope.MessageID || ids[1] != child.scope.MessageID || ids[2] != "00000000-0000-4000-8000-000000000040" {
		t.Fatal("incorrect transitive subject closure", ids)
	}
	// An opaque message ID is not part of the decoded subject document.
	matcher = func(_ context.Context, _ StoredMessage, body []byte) (bool, error) {
		return bytes.Contains(body, []byte(root.scope.MessageID)), nil
	}
	if _, err := f.journal.WithSubjectExport(f.operational(t, f.red.scope.TenantID), HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, exportRecordAuthority, matcher, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		n, err := stream(io.Discard)
		if n != 0 {
			t.Error("metadata ID was matched as subject content")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Ancestor ciphertext shares the positive page-byte resource. A matching
	// root must not let its unmatched child read an extra unbudgeted body.
	stored, err := f.journal.Lookup(child.requestContext(t), child.scope.ConversationID, Revision{MessageID: child.scope.MessageID, Revision: 1}, 1<<20, child.authorizeHistory)
	if err != nil {
		t.Fatal(err)
	}
	matcher = func(_ context.Context, _ StoredMessage, body []byte) (bool, error) {
		return bytes.Contains(body, []byte("MATCH_SUBJECT")), nil
	}
	if _, err := f.journal.WithSubjectExport(f.operational(t, f.red.scope.TenantID), HistoryBudget{Rows: 1, Bytes: stored.StoredBytes()}, allowActivityMaintenance, exportRecordAuthority, matcher, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		_, _ = stream(io.Discard)
		return nil
	}); !errors.Is(err, ErrMessageBudget) || f.active(t, f.red.scope.TenantID) != 0 {
		t.Fatal("ancestor read exceeded page resources or hid refusal", err)
	}
	// Matcher and per-record authority failures are never empty clean success,
	// even if an internal callback ignores the streaming error.
	marker := errors.New("owned subject matcher resource refusal")
	matcher = func(context.Context, StoredMessage, []byte) (bool, error) { return false, marker }
	if _, err := f.journal.WithSubjectExport(f.operational(t, f.red.scope.TenantID), HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, exportRecordAuthority, matcher, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		_, _ = stream(io.Discard)
		return nil
	}); !errors.Is(err, ErrJournalUnavailable) || f.active(t, f.red.scope.TenantID) != 0 {
		// Unknown callback detail is deliberately normalized at the storage
		// boundary. It must stay a refusal, not become an empty success.
		t.Fatal("ignored matcher failure lost its safe refusal or actual drain", err)
	}
	entered := false
	denied := func(context.Context, MessageScope, InputMetadata) error { return ErrMessageDenied }
	matcher = func(context.Context, StoredMessage, []byte) (bool, error) { entered = true; return true, nil }
	if _, err := f.journal.WithSubjectExport(f.operational(t, f.red.scope.TenantID), HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, denied, matcher, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		_, err := stream(io.Discard)
		return err
	}); !errors.Is(err, ErrMessageDenied) || entered {
		t.Fatal("selector became independent source authority", err)
	}
	if _, err := f.journal.WithSubjectExport(f.operational(t, f.red.scope.TenantID), HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, exportRecordAuthority, nil, func(context.Context, func(io.Writer) (int64, error)) error { return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing subject selector widened to full export", err)
	}
	// Simulate corrupted persisted ancestry in this disposable owned DB. The
	// FK remains valid, but the parent points forward and creates a cycle.
	restore := sync.OnceFunc(func() {
		if _, err := f.admin.Exec(context.Background(), `UPDATE flow_conversation_messages SET parent_message_id=NULL,parent_revision=NULL WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, f.red.scope.TenantID, root.scope.MessageID); err != nil {
			t.Error("owned ancestry restoration failed", err)
		}
	})
	t.Cleanup(restore)
	if tag, err := f.admin.Exec(t.Context(), `UPDATE flow_conversation_messages SET parent_message_id=$3::uuid,parent_revision=1 WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, f.red.scope.TenantID, root.scope.MessageID, "00000000-0000-4000-8000-000000000040"); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("owned ancestry fault was not installed", err)
	}
	badSourceEntered := false
	matcher = func(_ context.Context, record StoredMessage, body []byte) (bool, error) {
		scope := record.Scope()
		if scope.MessageID == root.scope.MessageID {
			badSourceEntered = true
		}
		return bytes.Contains(body, []byte("MATCH_SUBJECT")), nil
	}
	if _, err := f.journal.WithSubjectExport(f.operational(t, f.red.scope.TenantID), HistoryBudget{Rows: 1, Bytes: 1 << 20}, allowActivityMaintenance, exportRecordAuthority, matcher, func(_ context.Context, stream func(io.Writer) (int64, error)) error {
		_, err := stream(io.Discard)
		return err
	}); !errors.Is(err, ErrMessageIntegrity) || badSourceEntered {
		t.Fatal("invalid ancestry entered subject source or produced clean success", err, badSourceEntered)
	}
	restore()
}
