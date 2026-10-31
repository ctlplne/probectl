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
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

func TestHistoryJournalPostgresSourceFreeDispatch(t *testing.T) {
	admin, pool := journalFixture(t)
	if admin == nil {
		return
	}
	f := newMessageCodecFixture(t)
	blue := f
	otherOwner := f
	var err error
	blue.scope.TenantID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	otherOwner.scope.OwnerID, err = crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []*messageCodecFixture{&blue, &otherOwner} {
		fixture.context = tenancy.WithTenant(t.Context(), tenancy.ID(fixture.scope.TenantID))
		fixture.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, fixture.scope.TenantID, fixture.scope.OwnerID, fixture.credentialID, fixture.storedHash)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []string{f.scope.TenantID, blue.scope.TenantID} {
		if _, err := admin.Exec(f.context, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned dispatch fixture')`, tenant, "probectl-qa-beta-dispatch-"+strings.ReplaceAll(tenant, "-", "")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{f.scope.TenantID, blue.scope.TenantID}); err != nil {
			t.Error("owned dispatch tenant cleanup failed")
		}
	})
	journal := NewJournal(pool)
	admit := func(fixture messageCodecFixture, message string) PreparedInput {
		t.Helper()
		scope := fixture.scope
		scope.MessageID = message
		ctx := fixture.requestContext(t)
		allow := func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
			return fixture.authorize(ctx, fixture.scope, origin, required)
		}
		// Large encrypted source must not consume the separate header resource.
		body := []byte(`{"question":"` + strings.Repeat("owned source ", 10000) + `"}`)
		defer clear(body)
		prepared, err := fixture.codec.PrepareInput(ctx, scope, inputMetadata(), []string{"ai.query", "flow.read", "metrics.read"}, body, allow)
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.AdmitInput(ctx, prepared, allow); err != nil {
			t.Fatal(err)
		}
		return prepared
	}
	inputs := make([]PreparedInput, 3)
	for i := range inputs {
		id, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		inputs[i] = admit(f, id)
	}
	// Same conversation/message IDs in other tenant/owner lanes are independent.
	admit(blue, inputs[0].input.scope.MessageID)
	admit(otherOwner, inputs[0].input.scope.MessageID)
	allow := func(_ context.Context, tenant, owner string) error {
		if tenant != f.scope.TenantID || owner != f.scope.OwnerID {
			return ErrMessageDenied
		}
		return nil
	}
	budget := DispatchBudget{Rows: 1, HeaderBytes: 1 << 20, TimeLimit: 10 * time.Second}
	first, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, budget, allow)
	if err != nil || len(first.Candidates) != 1 || first.Next == nil {
		t.Fatal("source-free page unavailable", err)
	}
	seen := map[string]bool{}
	page := first
	for {
		for _, candidate := range page.Candidates {
			scope := candidate.Scope()
			if scope.TenantID != f.scope.TenantID || scope.OwnerID != f.scope.OwnerID || seen[scope.MessageID] {
				t.Fatal("foreign or duplicate candidate crossed owner RLS")
			}
			seen[scope.MessageID] = true
			if err := f.codec.BootstrapDispatch(f.context, candidate, allow, func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
				return f.authorize(ctx, f.scope, origin, required)
			}); err != nil {
				t.Fatal("original header provenance unavailable", err)
			}
		}
		if page.Next == nil {
			break
		}
		page, err = NewJournal(pool).DispatchPage(f.context, f.scope.OwnerID, page.Next, budget, allow)
		if err != nil {
			t.Fatal("fresh process could not continue source-free sweep", err)
		}
	}
	if len(seen) != len(inputs) {
		t.Fatal("metadata paging silently dropped retained work", len(seen))
	}
	for _, cursor := range []*DispatchCursor{first.Next} {
		if _, err := journal.DispatchPage(blue.context, blue.scope.OwnerID, cursor, budget, func(context.Context, string, string) error { return nil }); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("foreign tenant reused in-process cursor", err)
		}
		if _, err := journal.DispatchPage(f.context, otherOwner.scope.OwnerID, cursor, budget, func(context.Context, string, string) error { return nil }); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("foreign owner reused in-process cursor", err)
		}
	}
	bluePage, err := journal.DispatchPage(blue.context, blue.scope.OwnerID, nil, budget, func(context.Context, string, string) error { return nil })
	if err != nil || len(bluePage.Candidates) != 1 || bluePage.Next != nil || bluePage.Candidates[0].Scope().TenantID != blue.scope.TenantID {
		t.Fatal("independently healthy blue metadata lane failed", err)
	}
	if err := journal.FailDispatch(f.context, bluePage.Candidates[0], DispatchOriginInvalid, f.authorizeDispatch); err == nil {
		t.Fatal("red operational context terminated blue work")
	}
	if err := journal.FailDispatch(blue.context, bluePage.Candidates[0], DispatchOriginInvalid, blue.authorizeDispatch); err != nil {
		t.Fatal("independently healthy blue terminal mutation failed", err)
	}
	otherPage, err := journal.DispatchPage(otherOwner.context, otherOwner.scope.OwnerID, nil, budget, otherOwner.authorizeDispatch)
	if err != nil || len(otherPage.Candidates) != 1 || otherPage.Next != nil {
		t.Fatal("independently healthy same-tenant owner metadata lane failed", err)
	}
	if err := journal.FailDispatch(f.context, otherPage.Candidates[0], DispatchOriginInvalid, f.authorizeDispatch); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("one owner's operational authority terminated another owner's work", err)
	}
	if err := journal.FailDispatch(otherOwner.context, otherPage.Candidates[0], DispatchOriginInvalid, otherOwner.authorizeDispatch); err != nil {
		t.Fatal("independently authorized same-tenant owner cleanup failed", err)
	}
	for _, candidate := range []DispatchCandidate{bluePage.Candidates[0], otherPage.Candidates[0]} {
		var status string
		if err := admin.QueryRow(f.context, `SELECT status FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND job_id=$3::uuid`, candidate.Scope().TenantID, candidate.Scope().OwnerID, candidate.value.job).Scan(&status); err != nil || status != "failed" {
			t.Fatal("paired terminal lane did not commit its own independently authorized state", err)
		}
	}
	// Prove storage owner isolation with no owner predicate in the query.
	if err := tenancy.InTenant(f.context, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := bindOwner(ctx, sc, f.scope.OwnerID); err != nil {
			return err
		}
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_conversation_jobs`).Scan(&count); err != nil {
			return err
		}
		if count != len(inputs) {
			t.Fatal("predicate-free metadata read crossed tenant/owner boundary", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("exact header resources and atomic overflow refusal", func(t *testing.T) {
		size := len(first.Candidates[0].value.header)
		exact := budget
		exact.HeaderBytes = size
		if page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, exact, allow); err != nil || len(page.Candidates) != 1 {
			t.Fatal("exact header budget refused independently of large payload", err)
		}
		exact.HeaderBytes--
		if page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, exact, allow); !errors.Is(err, ErrMessageBudget) || page.Candidates != nil {
			t.Fatal("one-byte header overflow returned partial work", err)
		}
		exact.Rows, exact.HeaderBytes = 3, size
		if page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, exact, allow); !errors.Is(err, ErrMessageBudget) || page.Candidates != nil {
			t.Fatal("cumulative header cost returned partial page", err)
		}
	})

	t.Run("payload read privilege is unnecessary", func(t *testing.T) {
		// Narrow only this owned disposable table; restore before sibling subtests.
		if _, err := admin.Exec(f.context, `REVOKE SELECT ON public.flow_conversation_messages FROM probectl_app`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := admin.Exec(ctx, `GRANT SELECT ON public.flow_conversation_messages TO probectl_app`); err != nil {
				t.Error("owned dispatch table privilege restore failed")
			}
		})
		if _, err := admin.Exec(f.context, `GRANT SELECT(tenant_id,owner_id,conversation_id,message_id,revision,epoch,kind,private_header) ON public.flow_conversation_messages TO probectl_app`); err != nil {
			t.Fatal(err)
		}
		page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, budget, allow)
		if err != nil || len(page.Candidates) != 1 {
			t.Fatal("source-free dispatch required payload SELECT permission", err)
		}
		if err := tenancy.InTenant(f.context, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if err := bindOwner(ctx, sc, f.scope.OwnerID); err != nil {
				return err
			}
			var payload string
			return sc.Q.QueryRow(ctx, `SELECT private_payload FROM flow_conversation_messages LIMIT 1`).Scan(&payload)
		}); err == nil {
			t.Fatal("negative control could still read source payload")
		}
	})

	t.Run("current internal authority after read is mandatory", func(t *testing.T) {
		calls := 0
		page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, budget, func(context.Context, string, string) error {
			calls++
			if calls > 1 {
				return ErrMessageDenied
			}
			return nil
		})
		if !errors.Is(err, ErrMessageDenied) || page.Candidates != nil || calls != 2 {
			t.Fatal("late operational authority loss returned metadata", err, calls)
		}
	})

	t.Run("live leases and terminal jobs are absent expired takeover is present", func(t *testing.T) {
		selected := first.Candidates[0]
		scope := selected.Scope()
		worker, err := NewWorker(journal, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := worker.ClaimInput(f.requestContext(t), scope.ConversationID, Revision{MessageID: scope.MessageID, Revision: scope.Revision}, f.authorizeHistory)
		if err != nil {
			t.Fatal(err)
		}
		all := budget
		all.Rows = 10
		page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, all, allow)
		if err != nil || len(page.Candidates) != 2 {
			t.Fatal("active replica appeared in dispatch sweep", err)
		}
		if _, err := admin.Exec(f.context, `UPDATE flow_conversation_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND job_id=$3::uuid`, scope.TenantID, scope.OwnerID, lease.value.job); err != nil {
			t.Fatal(err)
		}
		page, err = journal.DispatchPage(f.context, f.scope.OwnerID, nil, all, allow)
		if err != nil || len(page.Candidates) != 3 {
			t.Fatal("expired replica not eligible for fresh authorization/takeover", err)
		}
		if err := journal.CancelInput(f.requestContext(t), scope.ConversationID, Revision{MessageID: scope.MessageID, Revision: scope.Revision}, f.authorizeHistory); err != nil {
			t.Fatal(err)
		}
		page, err = journal.DispatchPage(f.context, f.scope.OwnerID, nil, all, allow)
		if err != nil || len(page.Candidates) != 2 {
			t.Fatal("terminal job appeared in dispatch sweep", err)
		}
	})

	t.Run("lifecycle change invalidates continuation", func(t *testing.T) {
		if _, err := admin.Exec(f.context, `UPDATE flow_conversation_epochs SET generation=generation+1 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
			t.Fatal(err)
		}
		page, err := journal.DispatchPage(f.context, f.scope.OwnerID, first.Next, budget, allow)
		if !errors.Is(err, ErrJournalGeneration) || page.Candidates != nil {
			t.Fatal("stale lifecycle cursor continued", err)
		}
	})
}

func TestHistoryJournalPostgresSourceFreeTerminalCleanup(t *testing.T) {
	admin, pool := journalFixture(t)
	if admin == nil {
		return
	}
	f := newMessageCodecFixture(t)
	if _, err := admin.Exec(f.context, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned terminal fixture')`, f.scope.TenantID, "probectl-qa-beta-terminal-"+strings.ReplaceAll(f.scope.TenantID, "-", "")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `DELETE FROM tenants WHERE id=$1::uuid`, f.scope.TenantID); err != nil {
			t.Error("owned terminal tenant cleanup failed")
		}
	})
	journal := NewJournal(pool)
	newCandidate := func() DispatchCandidate {
		t.Helper()
		scope := f.scope
		var err error
		scope.ConversationID, err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		allow := func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
			return f.authorize(ctx, f.scope, origin, required)
		}
		prepared, err := f.codec.PrepareInput(f.requestContext(t), scope, inputMetadata(), []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"question":"terminal source remains private"}`), allow)
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.AdmitInput(f.requestContext(t), prepared, allow); err != nil {
			t.Fatal(err)
		}
		page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, DispatchBudget{Rows: 100, HeaderBytes: 1 << 20, TimeLimit: 10 * time.Second}, f.authorizeDispatch)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range page.Candidates {
			if candidate.Scope() == scope {
				return candidate
			}
		}
		t.Fatal("owned newly admitted terminal candidate missing")
		return DispatchCandidate{}
	}
	state := func(candidate DispatchCandidate) (string, uint64, uint64) {
		t.Helper()
		var status string
		var generation, cancellation uint64
		if err := admin.QueryRow(f.context, `SELECT status,lease_generation,cancel_revision FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND job_id=$3::uuid`, f.scope.TenantID, f.scope.OwnerID, candidate.value.job).Scan(&status, &generation, &cancellation); err != nil {
			t.Fatal(err)
		}
		return status, generation, cancellation
	}
	claim := func(candidate DispatchCandidate) (*Worker, WorkLease) {
		t.Helper()
		worker, err := NewWorker(journal, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		scope := candidate.Scope()
		lease, err := worker.ClaimInput(f.requestContext(t), scope.ConversationID, Revision{MessageID: scope.MessageID, Revision: scope.Revision}, f.authorizeHistory)
		if err != nil {
			t.Fatal(err)
		}
		return worker, lease
	}
	t.Run("no_payload_permission_key_or_creator_principal_needed", func(t *testing.T) {
		candidate := newCandidate()
		tenantcrypto.Reset()
		t.Cleanup(func() { tenantcrypto.SetPrimary(f.sealer) })
		if _, err := admin.Exec(f.context, `REVOKE SELECT ON public.flow_conversation_messages FROM probectl_app`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := admin.Exec(ctx, `GRANT SELECT ON public.flow_conversation_messages TO probectl_app`); err != nil {
				t.Error("owned terminal privilege restore failed")
			}
		})
		if err := journal.FailDispatch(f.context, candidate, DispatchOriginInvalid, f.authorizeDispatch); err != nil {
			t.Fatal("independent cleanup needed source or creator authority", err)
		}
		status, generation, cancellation := state(candidate)
		if status != "failed" || generation != 1 || cancellation != 1 {
			t.Fatal("terminal transition failed to fence all old workers", status, generation, cancellation)
		}
		var actor, reason string
		if err := admin.QueryRow(f.context, `SELECT actor,data->>'reason' FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.conversation.failed' AND target=$2`, f.scope.TenantID, candidate.Scope().MessageID).Scan(&actor, &reason); err != nil || actor != "system:flow-conversation" || reason != "origin_invalid" {
			t.Fatal("terminal metadata audit missing or misattributed", err, actor, reason)
		}
	})
	t.Run("mandatory_audit_refusal_rolls_back", func(t *testing.T) {
		candidate := newCandidate()
		original := journal.record
		journal.record = func(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
			return errors.New("owned terminal audit refusal")
		}
		err := journal.FailDispatch(f.context, candidate, DispatchSourceExpired, f.authorizeDispatch)
		journal.record = original
		status, generation, cancellation := state(candidate)
		if err == nil || status != "queued" || generation != 0 || cancellation != 0 {
			t.Fatal("audit failure left terminal mutation", err, status, generation, cancellation)
		}
		if err := journal.FailDispatch(f.context, candidate, DispatchSourceExpired, f.authorizeDispatch); err != nil {
			t.Fatal("healthy terminal retry failed", err)
		}
	})
	t.Run("new_active_replica_cannot_be_terminated", func(t *testing.T) {
		candidate := newCandidate()
		worker, lease := claim(candidate)
		if err := journal.FailDispatch(f.context, candidate, DispatchOriginInvalid, f.authorizeDispatch); !errors.Is(err, ErrJournalLease) {
			t.Fatal("stale discovery terminated a newly claimed replica", err)
		}
		if err := worker.CheckLease(f.requestContext(t), lease, f.authorizeHistory); err != nil {
			t.Fatal("refused cleanup damaged active replica", err)
		}
	})
	t.Run("expired_processing_candidate_and_corrupt_header", func(t *testing.T) {
		candidate := newCandidate()
		_, lease := claim(candidate)
		if _, err := admin.Exec(f.context, `UPDATE flow_conversation_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND job_id=$3::uuid`, f.scope.TenantID, f.scope.OwnerID, candidate.value.job); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(f.context, `UPDATE flow_conversation_messages SET private_header='' WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND conversation_id=$3::uuid`, f.scope.TenantID, f.scope.OwnerID, candidate.Scope().ConversationID); err != nil {
			t.Fatal(err)
		}
		page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, DispatchBudget{Rows: 100, HeaderBytes: 1 << 20, TimeLimit: 10 * time.Second}, f.authorizeDispatch)
		if err != nil {
			t.Fatal("corrupt header made source-free maintenance impossible", err)
		}
		var expired DispatchCandidate
		for _, value := range page.Candidates {
			if value.Scope() == candidate.Scope() {
				expired = value
			}
		}
		if expired.value == nil || expired.value.generation != lease.value.generation {
			t.Fatal("expired corrupt candidate missing")
		}
		if err := f.codec.BootstrapDispatch(f.context, expired, f.authorizeDispatch, f.authorize); !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("corrupt header acquired origin/source authority", err)
		}
		if err := journal.FailDispatch(f.context, expired, DispatchSourceInvalid, f.authorizeDispatch); err != nil {
			t.Fatal("source-free corrupt-input cleanup failed", err)
		}
		status, generation, cancellation := state(expired)
		if status != "failed" || generation != expired.value.generation+1 || cancellation != expired.value.cancellation+1 {
			t.Fatal("expired processing cleanup did not advance fences", status)
		}
	})
	t.Run("stale_expired_generation_cannot_terminate_later_expired_replica", func(t *testing.T) {
		candidate := newCandidate()
		claim(candidate)
		expire := func() {
			t.Helper()
			if _, err := admin.Exec(f.context, `UPDATE flow_conversation_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND owner_id=$2::uuid AND job_id=$3::uuid`, f.scope.TenantID, f.scope.OwnerID, candidate.value.job); err != nil {
				t.Fatal(err)
			}
		}
		discover := func() DispatchCandidate {
			t.Helper()
			page, err := journal.DispatchPage(f.context, f.scope.OwnerID, nil, DispatchBudget{Rows: 100, HeaderBytes: 1 << 20, TimeLimit: 10 * time.Second}, f.authorizeDispatch)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range page.Candidates {
				if value.Scope() == candidate.Scope() {
					return value
				}
			}
			t.Fatal("expired replica missing from owned sweep")
			return DispatchCandidate{}
		}
		expire()
		old := discover()
		_, next := claim(candidate)
		expire()
		if err := journal.FailDispatch(f.context, old, DispatchSourceInvalid, f.authorizeDispatch); !errors.Is(err, ErrJournalLease) {
			t.Fatal("stale failure classification terminated a later replica generation", err)
		}
		status, generation, _ := state(candidate)
		if status != "processing" || generation != next.value.generation {
			t.Fatal("refused stale cleanup damaged newer resumable work")
		}
		if err := journal.FailDispatch(f.context, discover(), DispatchAuthorityRefused, f.authorizeDispatch); err != nil {
			t.Fatal("fresh independently authorized terminal cleanup failed", err)
		}
	})
	t.Run("cancellation_and_epoch_refuse_stale_cleanup", func(t *testing.T) {
		candidate := newCandidate()
		scope := candidate.Scope()
		if err := journal.CancelInput(f.requestContext(t), scope.ConversationID, Revision{MessageID: scope.MessageID, Revision: scope.Revision}, f.authorizeHistory); err != nil {
			t.Fatal(err)
		}
		if err := journal.FailDispatch(f.context, candidate, DispatchAuthorityRefused, f.authorizeDispatch); !errors.Is(err, ErrJournalLease) {
			t.Fatal("stale cleanup changed explicitly canceled work", err)
		}
		candidate = newCandidate()
		if _, err := admin.Exec(f.context, `UPDATE flow_conversation_epochs SET generation=generation+1 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
			t.Fatal(err)
		}
		if err := journal.FailDispatch(f.context, candidate, DispatchOriginInvalid, f.authorizeDispatch); !errors.Is(err, ErrJournalGeneration) {
			t.Fatal("terminal cleanup bypassed lifecycle epoch", err)
		}
	})
}
