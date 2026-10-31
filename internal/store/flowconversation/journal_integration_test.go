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
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// These temporary tables exist only in the explicitly owned test database and
// are removed before returning. They are not a product migration or completed
// history/queue/lifecycle service.
func journalFixture(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		t.Fatal("journal fixture database unavailable")
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "journal fixture PostgreSQL unavailable")
		return nil, nil
	}
	testsupport.LockPostgresPublicCatalog(t, admin)
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, admin); err != nil {
		t.Fatal(err)
	}
	base := ownerFixtureRuntime(ctx, t, admin)
	config := base.Config().Copy()
	config.MaxConns = 4 // Fence lease and routed app transaction use separate connections.
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("journal restricted runtime pool unavailable")
	}
	t.Cleanup(pool.Close)
	var tls bool
	if err := pool.QueryRow(ctx, `SELECT COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false)`).Scan(&tls); err != nil {
		t.Fatal(err)
	}
	if tls {
		t.Log("history journal runtime TLS transport verified")
	} else {
		t.Log("journal proof uses plaintext CI fixture; not TLS proof")
	}
	testsupport.InstallFlowHistoryFixture(ctx, t, admin, tenancy.FlowHistoryOwnerBoundaryPlan)
	return admin, pool
}

func TestHistoryJournalPostgresAtomicAdmissionEpochAndRollback(t *testing.T) {
	admin, pool := journalFixture(t)
	if admin == nil {
		return
	}
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	blueID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{f.scope.TenantID, blueID} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned journal fixture')`, tenant, "probectl-qa-beta-journal-"+strings.ReplaceAll(tenant, "-", "")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{f.scope.TenantID, blueID}); err != nil {
			t.Error("owned journal tenant cleanup failed")
		}
	})
	journal := NewJournal(pool)
	generation, err := journal.CandidateEpoch(ctx)
	if err != nil || generation != 1 {
		t.Fatal("initial candidate generation unavailable", err)
	}
	var epochs int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_epochs`).Scan(&epochs); err != nil || epochs != 0 {
		t.Fatal("candidate read created durable state", err)
	}
	meta := inputMetadata()
	meta.FrozenAt = meta.FrozenAt.Truncate(time.Second).Add(123456789 * time.Nanosecond)
	body := []byte(`{"question":"retained bob@example.test","number":18446744073709551617}`)
	prepared, err := f.codec.PrepareInput(ctx, f.scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, body, f.authorize)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.AdmitInput(ctx, prepared, f.authorize); err != nil {
		t.Fatal("atomic input admission failed", err)
	}
	assertCounts := func(messages, jobs, events int) {
		t.Helper()
		var gotMessages, gotJobs, gotEvents int
		if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM flow_conversation_messages WHERE tenant_id=$1::uuid),(SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid),(SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.conversation.input')`, f.scope.TenantID).Scan(&gotMessages, &gotJobs, &gotEvents); err != nil || gotMessages != messages || gotJobs != jobs || gotEvents != events {
			t.Fatal("input/job/audit transaction counts disagree", gotMessages, gotJobs, gotEvents, err)
		}
	}
	assertCounts(1, 1, 1)
	otherOwner := f
	otherOwner.scope.OwnerID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	otherOwner.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, f.scope.TenantID, otherOwner.scope.OwnerID, f.credentialID, f.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	otherContext := otherOwner.requestContext(t)
	if err := journal.AdmitInput(otherContext, prepared, otherOwner.authorize); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("same-tenant foreign owner adopted private prepared input", err)
	}
	if err := tenancy.InTenant(otherContext, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `SELECT set_config('probectl.flow_history_lifecycle','authorized',true)`); err != nil {
			return err
		}
		if _, _, err := bindRequestOwner(ctx, sc); err != nil {
			return err
		}
		var n int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_messages`).Scan(&n); err != nil || n != 0 {
			t.Fatal("current owner binding retained maintenance mode or read foreign source", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var frozen, header, payload, status string
	if err := admin.QueryRow(ctx, `SELECT frozen_at,private_header,private_payload FROM flow_conversation_messages WHERE tenant_id=$1::uuid`, f.scope.TenantID).Scan(&frozen, &header, &payload); err != nil {
		t.Fatal(err)
	}
	if frozen != meta.FrozenAt.UTC().Format(time.RFC3339Nano) || strings.Contains(header+payload, "bob@example.test") || header != prepared.input.sealed.parts.header || payload != prepared.input.sealed.parts.payload {
		t.Fatal("stored input lost exact clock or private encrypted pair")
	}
	if err := admin.QueryRow(ctx, `SELECT status FROM flow_conversation_jobs WHERE tenant_id=$1::uuid`, f.scope.TenantID).Scan(&status); err != nil || status != "queued" {
		t.Fatal("job not durably queued", err)
	}
	if err := journal.AdmitInput(ctx, prepared, f.authorize); !errors.Is(err, ErrJournalConflict) {
		t.Fatal("duplicate input was silently rewritten", err)
	}
	assertCounts(1, 1, 1)
	child := func(parent *Revision) PreparedInput {
		t.Helper()
		scope := f.scope
		var err error
		scope.MessageID, err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		m := meta
		m.Parent = parent
		value, err := f.codec.PrepareInput(ctx, scope, m, []string{"ai.query", "flow.read", "metrics.read"}, body, func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
			return f.authorize(ctx, f.scope, origin, required)
		})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	allowChild := func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
		return f.authorize(ctx, f.scope, origin, required)
	}
	parent := &Revision{MessageID: f.scope.MessageID, Revision: f.scope.Revision}
	followup := child(parent)
	oldRecord := journal.record
	journal.record = func(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
		return errors.New("injected audit refusal")
	}
	if err := journal.AdmitInput(ctx, followup, allowChild); !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("audit refusal committed private input/job", err)
	}
	assertCounts(1, 1, 1)
	journal.record = oldRecord
	if err := journal.AdmitInput(ctx, followup, allowChild); err != nil {
		t.Fatal("healthy retry after audit rollback failed", err)
	}
	assertCounts(2, 2, 2)
	missing := child(&Revision{MessageID: followup.input.scope.MessageID, Revision: 99})
	if err := journal.AdmitInput(ctx, missing, allowChild); !errors.Is(err, ErrJournalConflict) {
		t.Fatal("missing explicit parent revision admitted", err)
	}
	assertCounts(2, 2, 2)
	stale := child(parent)
	if _, err := admin.Exec(ctx, `UPDATE flow_conversation_epochs SET generation=generation+1 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
		t.Fatal(err)
	}
	if err := journal.AdmitInput(ctx, stale, allowChild); !errors.Is(err, ErrJournalGeneration) {
		t.Fatal("stale prepared input survived lifecycle generation advance", err)
	}
	assertCounts(2, 2, 2)
	if generation, err := NewJournal(pool).CandidateEpoch(ctx); err != nil || generation != 2 {
		t.Fatal("persisted generation did not survive journal reconstruction", err)
	}
	f.scope.Epoch = 2
	inflight := child(parent)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	journal.record = func(ctx context.Context, sc tenancy.Scope, actor, action, target string, data map[string]any) error {
		close(entered)
		select {
		case <-release:
			return oldRecord(ctx, sc, actor, action, target, data)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	admitted := make(chan error, 1)
	go func() { admitted <- journal.AdmitInput(ctx, inflight, allowChild) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("in-flight journal did not reach transactional audit barrier")
	}
	offboardPID := make(chan int, 1)
	offboarded := make(chan error, 1)
	go func() {
		offboarded <- tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
			var pid int
			if err := q.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			offboardPID <- pid
			if err := tenancy.LockTenantWrites(ctx, q, f.scope.TenantID); err != nil {
				return err
			}
			_, err := q.Exec(ctx, `UPDATE tenants SET status='offboarding',audit_write_fenced_at=clock_timestamp() WHERE id=$1::uuid`, f.scope.TenantID)
			return err
		})
	}()
	var pid int
	select {
	case pid = <-offboardPID:
	case <-ctx.Done():
		t.Fatal("offboarding did not enter its exclusive writer lease")
	}
	blocked := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := admin.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("exclusive offboarding lease did not wait for in-flight journal admission")
	}
	select {
	case err := <-offboarded:
		t.Fatal("offboarding completed while old admission was inside its writer lease", err)
	default:
	}
	t.Log("history journal offboarding observed blocked on actual PostgreSQL writer lease")
	releaseOnce.Do(func() { close(release) })
	if err := <-admitted; err != nil {
		t.Fatal("admission already inside shared writer lease did not finish", err)
	}
	if err := <-offboarded; err != nil {
		t.Fatal("exclusive offboarding failed after admission drained", err)
	}
	journal.record = oldRecord
	assertCounts(3, 3, 3)
	if err := journal.AdmitInput(ctx, child(parent), allowChild); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatal("full tenant writer fence admitted private input", err)
	}
	assertCounts(3, 3, 3)
	// The other tenant remains writable under the same runtime role, key and
	// owner/conversation/message IDs; one tenant's fence cannot affect it.
	blue := f
	blue.scope.TenantID = blueID
	blue.scope.Epoch = 1
	blue.context = tenancy.WithTenant(t.Context(), tenancy.ID(blueID))
	blue.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, blueID, f.scope.OwnerID, f.credentialID, f.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	blueContext := blue.requestContext(t)
	bluePrepared, err := blue.codec.PrepareInput(blueContext, blue.scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"question":"healthy blue"}`), blue.authorize)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.AdmitInput(blueContext, bluePrepared, blue.authorize); err != nil {
		t.Fatal("red lifecycle fence contaminated blue admission", err)
	}
	if err := journal.AdmitInput(blueContext, prepared, blue.authorize); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("blue current actor adopted red prepared input", err)
	}
	if err := tenancy.InTenant(blueContext, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, _, err := bindRequestOwner(ctx, sc); err != nil {
			return err
		}
		var n int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_messages`).Scan(&n); err != nil || n != 1 {
			t.Fatal("predicate-free RLS read crossed tenant boundary", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var redCount, blueCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FILTER(WHERE tenant_id=$1::uuid),count(*) FILTER(WHERE tenant_id=$2::uuid) FROM flow_conversation_messages`, f.scope.TenantID, blueID).Scan(&redCount, &blueCount); err != nil || redCount != 3 || blueCount != 1 {
		t.Fatal("paired tenant durable rows changed unexpectedly", redCount, blueCount, err)
	}
}
