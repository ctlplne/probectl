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
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryJournalPostgresWorkerLeasesAndCancellation(t *testing.T) {
	admin, pool := journalFixture(t)
	if admin == nil {
		return
	}
	f := newMessageCodecFixture(t)
	ctx := f.requestContext(t)
	journal := NewJournal(pool)
	if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned lease fixture')`, f.scope.TenantID, "probectl-qa-beta-lease-"+strings.ReplaceAll(f.scope.TenantID, "-", "")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DELETE FROM tenants WHERE id=$1::uuid`, f.scope.TenantID); err != nil {
			t.Error("owned worker tenant cleanup failed")
		}
	})
	authorize := func(_ context.Context, tenant, owner string, origin auth.WorkerCredentialRef) error {
		if tenant != f.scope.TenantID || owner != f.scope.OwnerID || !sameRequestOrigin(origin, f.origin) {
			return ErrMessageDenied
		}
		return nil
	}
	newInput := func(expiry time.Time) PreparedInput {
		t.Helper()
		scope := f.scope
		var err error
		scope.MessageID, err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		meta := inputMetadata()
		meta.ExpiresAt = expiry
		prepared, err := f.codec.PrepareInput(ctx, scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"question":"private lease input"}`), func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
			return f.authorize(ctx, f.scope, origin, required)
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.AdmitInput(ctx, prepared, func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
			return f.authorize(ctx, f.scope, origin, required)
		}); err != nil {
			t.Fatal(err)
		}
		return prepared
	}
	newWorker := func() *Worker {
		t.Helper()
		worker, err := NewWorker(journal, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return worker
	}
	revision := func(input PreparedInput) Revision {
		return Revision{MessageID: input.input.scope.MessageID, Revision: input.input.scope.Revision}
	}
	claim := func(w *Worker, input PreparedInput) WorkLease {
		t.Helper()
		value, err := w.ClaimInput(ctx, f.scope.ConversationID, revision(input), authorize)
		if err != nil {
			t.Fatal("owned input claim refused", err)
		}
		return value
	}
	counts := func(action string) int {
		t.Helper()
		var n int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND action=$2`, f.scope.TenantID, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("competing replicas renewal takeover and stale values", func(t *testing.T) {
		input := newInput(time.Now().Add(time.Hour))
		workers := []*Worker{newWorker(), newWorker()}
		leases := make([]WorkLease, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				leases[i], errs[i] = workers[i].ClaimInput(ctx, f.scope.ConversationID, revision(input), authorize)
			}()
		}
		wg.Wait()
		winner := 0
		if errs[0] != nil {
			winner = 1
		}
		if errs[winner] != nil || !errors.Is(errs[1-winner], ErrJournalLease) || counts("flow.conversation.claim") != 1 {
			t.Fatal("competing replicas did not yield exactly one claim", errs)
		}
		w, old := workers[winner], leases[winner]
		if err := w.CheckLease(ctx, old, authorize); err != nil {
			t.Fatal("live current lease refused", err)
		}
		live, err := w.Renew(ctx, old, authorize)
		if err != nil || live.value.generation != old.value.generation+1 {
			t.Fatal("renewal did not advance lease fence", err)
		}
		if err := w.CheckLease(ctx, old, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("old value remained current after renewal", err)
		}
		if _, err := w.Renew(ctx, old, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("old value renewed after replacement", err)
		}
		if err := w.CheckLease(ctx, live, authorize); err != nil {
			t.Fatal("renewed current lease refused", err)
		}
		// Preserve the exact database value in this owned test handle: refusal
		// must exercise DB-clock expiry, not just a mismatched until value.
		expired := *live.value
		if err := admin.QueryRow(ctx, `UPDATE flow_conversation_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND job_id=$2::uuid RETURNING lease_until`, f.scope.TenantID, live.value.job).Scan(&expired.until); err != nil {
			t.Fatal(err)
		}
		if err := w.CheckLease(ctx, WorkLease{&expired}, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("database-expired exact lease remained live", err)
		}
		if _, err := w.Renew(ctx, WorkLease{&expired}, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("expired owner renewed lease", err)
		}
		takeover := claim(workers[1-winner], input)
		if takeover.value.generation != live.value.generation+1 || takeover.value.worker == live.value.worker {
			t.Fatal("takeover did not advance durable fence")
		}
		if err := w.CheckLease(ctx, live, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("stale replica passed after takeover", err)
		}
		if err := journal.CancelInput(ctx, f.scope.ConversationID, revision(input), authorize); err != nil {
			t.Fatal("explicit cancel refused", err)
		}
		if err := workers[1-winner].CheckLease(ctx, takeover, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("canceled replica retained lease", err)
		}
		if _, err := workers[1-winner].Renew(ctx, takeover, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("canceled lease revived", err)
		}
		if _, err := workers[1-winner].ClaimInput(ctx, f.scope.ConversationID, revision(input), authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("canceled job was claimed again", err)
		}
		var status string
		var cancellation uint64
		var cleared bool
		if err := admin.QueryRow(ctx, `SELECT status,cancel_revision,worker_id IS NULL AND lease_until IS NULL FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND job_id=$2::uuid`, f.scope.TenantID, takeover.value.job).Scan(&status, &cancellation, &cleared); err != nil || status != "canceled" || cancellation != 1 || !cleared {
			t.Fatal("cancel did not fence and clear lease metadata", err)
		}
	})

	t.Run("mandatory audit rollback for claim renew and cancel", func(t *testing.T) {
		input := newInput(time.Now().Add(time.Hour))
		w := newWorker()
		original := journal.record
		refuse := func(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
			return errors.New("owned audit refusal")
		}
		journal.record = refuse
		_, err := w.ClaimInput(ctx, f.scope.ConversationID, revision(input), authorize)
		journal.record = original
		if !errors.Is(err, ErrJournalUnavailable) {
			t.Fatal("claim ignored mandatory audit refusal", err)
		}
		lease := claim(w, input) // Refused claim must have rolled back to queued.
		beforeRenew, beforeCancel := counts("flow.conversation.renew"), counts("flow.conversation.cancel")
		journal.record = refuse
		_, renewErr := w.Renew(ctx, lease, authorize)
		cancelErr := journal.CancelInput(ctx, f.scope.ConversationID, revision(input), authorize)
		journal.record = original
		if !errors.Is(renewErr, ErrJournalUnavailable) || !errors.Is(cancelErr, ErrJournalUnavailable) {
			t.Fatal("mutation ignored mandatory audit refusal", renewErr, cancelErr)
		}
		if err := w.CheckLease(ctx, lease, authorize); err != nil || counts("flow.conversation.renew") != beforeRenew || counts("flow.conversation.cancel") != beforeCancel {
			t.Fatal("audit refusal left a lease/cancel mutation", err)
		}
	})

	t.Run("database expiry retention cap nullable policy and lifecycle epoch", func(t *testing.T) {
		w := newWorker()
		deadline := StorageDeadline(time.Now().Add(30 * time.Second))
		input := newInput(deadline)
		lease := claim(w, input)
		if !lease.Until().Equal(deadline) {
			t.Fatal("claim extended immutable input deadline")
		}
		renewed, err := w.Renew(ctx, lease, authorize)
		if err != nil || !renewed.Until().Equal(deadline) || renewed.value.generation == lease.value.generation {
			t.Fatal("capped renewal did not replace exact lease", err)
		}
		if err := w.CheckLease(ctx, lease, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("same-until capped renewal retained an old generation", err)
		}
		forever := newInput(time.Time{})
		if live := claim(w, forever); !live.Until().After(time.Now()) {
			t.Fatal("nullable input policy produced an unbounded lease")
		}
		expired := newInput(time.Now().Add(time.Hour))
		if _, err := admin.Exec(ctx, `UPDATE flow_conversation_messages SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, f.scope.TenantID, expired.input.scope.MessageID); err != nil {
			t.Fatal(err)
		}
		if _, err := w.ClaimInput(ctx, f.scope.ConversationID, revision(expired), authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("expired input became runnable", err)
		}
		if _, err := admin.Exec(ctx, `UPDATE flow_conversation_epochs SET generation=generation+1 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
			t.Fatal(err)
		}
		if err := w.CheckLease(ctx, renewed, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("old lifecycle epoch remained runnable", err)
		}
		if _, err := w.Renew(ctx, renewed, authorize); !errors.Is(err, ErrJournalGeneration) {
			t.Fatal("old lifecycle epoch renewed", err)
		}
		if err := journal.CancelInput(ctx, f.scope.ConversationID, revision(input), authorize); err != nil {
			t.Fatal("current owner could not stop old-epoch metadata", err)
		}
		if _, err := admin.Exec(ctx, `UPDATE flow_conversation_epochs SET generation=1 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fresh current owner can cancel old-origin queued work only", func(t *testing.T) {
		input := newInput(time.Now().Add(time.Hour))
		hash, err := crypto.Random(32)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, f.scope.TenantID, f.scope.OwnerID, f.credentialID, hash)
		clear(hash)
		if err != nil {
			t.Fatal(err)
		}
		p, err := auth.WithWorkerCredential(&auth.Principal{TenantID: f.scope.TenantID, UserID: f.scope.OwnerID, ViaBearerToken: true}, ref)
		if err != nil {
			t.Fatal(err)
		}
		current := auth.WithPrincipal(ctx, p)
		fresh := func(_ context.Context, tenant, owner string, actual auth.WorkerCredentialRef) error {
			if tenant != f.scope.TenantID || owner != f.scope.OwnerID || !sameRequestOrigin(ref, actual) {
				return ErrMessageDenied
			}
			return nil
		}
		if err := journal.CancelInput(current, f.scope.ConversationID, revision(input), fresh); err != nil {
			t.Fatal("fresh current owner could not cancel old queued origin", err)
		}
		if _, err := newWorker().ClaimInput(ctx, f.scope.ConversationID, revision(input), authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("old origin revived explicitly canceled work", err)
		}
		if _, err := newWorker().ClaimInput(current, f.scope.ConversationID, revision(input), fresh); !errors.Is(err, ErrJournalLease) {
			t.Fatal("fresh origin revived explicitly canceled work", err)
		}
	})

	t.Run("owner and tenant storage boundaries with healthy sibling", func(t *testing.T) {
		input := newInput(time.Now().Add(time.Hour))
		w := newWorker()
		allow := func(context.Context, string, string, auth.WorkerCredentialRef) error { return nil }
		for _, foreignTenant := range []bool{false, true} {
			other := f
			id, err := crypto.UUIDv4()
			if err != nil {
				t.Fatal(err)
			}
			if foreignTenant {
				other.scope.TenantID = id
				other.context = tenancy.WithTenant(t.Context(), tenancy.ID(id))
				if _, err := admin.Exec(ctx, `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned sibling lease fixture')`, id, "probectl-qa-beta-lease-"+strings.ReplaceAll(id, "-", "")); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if _, err := admin.Exec(cleanup, `DELETE FROM tenants WHERE id=$1::uuid`, id); err != nil {
						t.Error(err)
					}
				})
			} else {
				other.scope.OwnerID = id
			}
			other.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, other.scope.TenantID, other.scope.OwnerID, other.credentialID, other.storedHash)
			if err != nil {
				t.Fatal(err)
			}
			foreign := other.requestContext(t)
			if _, err := w.ClaimInput(foreign, f.scope.ConversationID, revision(input), allow); err == nil {
				t.Fatal("foreign owner/tenant claimed source-free job")
			}
			if err := journal.CancelInput(foreign, f.scope.ConversationID, revision(input), allow); err == nil {
				t.Fatal("foreign owner/tenant canceled job")
			}
			if foreignTenant {
				other.scope.MessageID, err = crypto.UUIDv4()
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := other.codec.PrepareInput(foreign, other.scope, inputMetadata(), []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"question":"sibling"}`), other.authorize)
				if err != nil {
					t.Fatal(err)
				}
				if err := journal.AdmitInput(foreign, prepared, other.authorize); err != nil {
					t.Fatal("healthy sibling admission refused", err)
				}
				sibling, err := w.ClaimInput(foreign, other.scope.ConversationID, revision(prepared), allow)
				if err != nil || w.CheckLease(foreign, sibling, allow) != nil {
					t.Fatal("healthy sibling lease refused", err)
				}
				source, err := journal.Lookup(foreign, other.scope.ConversationID, revision(prepared), 1<<20, allow)
				if err != nil {
					t.Fatal(err)
				}
				scope := other.scope
				scope.MessageID, err = crypto.UUIDv4()
				if err != nil {
					t.Fatal(err)
				}
				meta := source.Metadata()
				parent := revision(prepared)
				meta.Parent = &parent
				authorizeSource := func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
					return other.authorize(ctx, other.scope, origin, required)
				}
				proposal, err := other.codec.PrepareProposal(foreign, sibling, source, scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"proposal":"healthy blue storage fixture"}`), authorizeSource)
				if err != nil {
					t.Fatal("healthy sibling proposal preparation refused", err)
				}
				if _, err := w.PublishProposal(ctx, sibling, proposal, authorizeSource); !errors.Is(err, ErrMessageDenied) {
					t.Fatal("red context adopted blue proposal publication", err)
				}
				published, err := w.PublishProposal(foreign, sibling, proposal, authorizeSource)
				if err != nil || published.Proposal() == nil || published.Proposal().MessageID != scope.MessageID {
					t.Fatal("healthy sibling proposal publication refused", err)
				}
			}
		}
		lease := claim(w, input)
		if err := w.CheckLease(ctx, lease, authorize); err != nil {
			t.Fatal("foreign attempts damaged healthy owner", err)
		}
	})

	// These are real storage publications with simple private JSON fixtures;
	// they do not claim the typed planner, model, confirmation or result phases.
	prepareProposal := func(w *Worker, input PreparedInput) (WorkLease, PreparedProposal, AuthorizeMessage) {
		t.Helper()
		lease := claim(w, input)
		source, err := journal.Lookup(ctx, f.scope.ConversationID, revision(input), 1<<20, authorize)
		if err != nil {
			t.Fatal(err)
		}
		scope := source.Scope()
		scope.MessageID, err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		meta := source.Metadata()
		parent := revision(input)
		meta.Parent = &parent
		check := func(ctx context.Context, _ MessageScope, origin auth.WorkerCredentialRef, required []string) error {
			return f.authorize(ctx, f.scope, origin, required)
		}
		proposal, err := f.codec.PrepareProposal(ctx, lease, source, scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"proposal":"private immutable storage fixture","exact":18446744073709551617}`), check)
		if err != nil {
			t.Fatal(err)
		}
		return lease, proposal, check
	}
	t.Run("atomic encrypted proposal and recoverable processing lease", func(t *testing.T) {
		w := newWorker()
		input := newInput(time.Now().Add(time.Hour))
		lease, proposal, check := prepareProposal(w, input)
		before := counts("flow.conversation.proposal")
		published, err := w.PublishProposal(ctx, lease, proposal, check)
		if err != nil || published.value.generation != lease.value.generation+1 || !published.Until().Equal(lease.Until()) {
			t.Fatal("proposal did not atomically advance lease without extending it", err)
		}
		ref := published.Proposal()
		if ref == nil || ref.MessageID != proposal.value.scope.MessageID || ref.Revision != proposal.value.scope.Revision {
			t.Fatal("published lease lost immutable proposal ref")
		}
		ref.MessageID = "caller mutation"
		if published.Proposal().MessageID != proposal.value.scope.MessageID {
			t.Fatal("proposal ref getter exposed mutable lease state")
		}
		var status, id string
		var generation uint64
		if err := admin.QueryRow(ctx, `SELECT status,proposal_message_id,lease_generation FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND job_id=$2::uuid`, f.scope.TenantID, lease.value.job).Scan(&status, &id, &generation); err != nil || status != "processing" || id != proposal.value.scope.MessageID || generation != published.value.generation || counts("flow.conversation.proposal") != before+1 {
			t.Fatal("proposal/job/audit transaction disagreed or completed an unanswered question", err)
		}
		stored, err := journal.Lookup(ctx, f.scope.ConversationID, *published.Proposal(), 1<<20, authorize)
		if err != nil || stored.Kind() != "proposal" || stored.Metadata().Parent == nil || *stored.Metadata().Parent != revision(input) || stored.Position() <= proposal.value.input.Position() {
			t.Fatal("immutable proposal storage binding lost", err)
		}
		body, err := f.codec.Open(ctx, stored.Scope(), stored.Ciphertext(), check)
		if err != nil || !bytes.Contains(body, []byte(`18446744073709551617`)) {
			t.Fatal("encrypted proposal changed exact body", err)
		}
		clear(body)
		if err := w.CheckLease(ctx, lease, authorize); !errors.Is(err, ErrJournalLease) {
			t.Fatal("pre-publication lease remained current", err)
		}
		if _, err := w.PublishProposal(ctx, lease, proposal, check); !errors.Is(err, ErrJournalLease) {
			t.Fatal("duplicate proposal changed immutable history", err)
		}
		if err := w.CheckLease(ctx, published, authorize); err != nil {
			t.Fatal("current published processing lease refused", err)
		}
		if _, err := admin.Exec(ctx, `UPDATE flow_conversation_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND job_id=$2::uuid`, f.scope.TenantID, lease.value.job); err != nil {
			t.Fatal(err)
		}
		recovered := claim(newWorker(), input)
		if recovered.Proposal() == nil || *recovered.Proposal() != *published.Proposal() {
			t.Fatal("takeover lost the already published immutable proposal")
		}
	})
	for _, fault := range []string{"audit", "cancel", "epoch", "expired-input", "paired-rotation", "authority"} {
		t.Run("proposal refusal rolls back "+fault, func(t *testing.T) {
			w := newWorker()
			input := newInput(time.Now().Add(time.Hour))
			lease, proposal, check := prepareProposal(w, input)
			before := counts("flow.conversation.proposal")
			original := journal.record
			defer func() { journal.record = original }()
			switch fault {
			case "audit":
				journal.record = func(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
					return errors.New("owned proposal audit refusal")
				}
			case "cancel":
				if err := journal.CancelInput(ctx, f.scope.ConversationID, revision(input), authorize); err != nil {
					t.Fatal(err)
				}
			case "epoch":
				if _, err := admin.Exec(ctx, `UPDATE flow_conversation_epochs SET generation=2 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := admin.Exec(ctx, `UPDATE flow_conversation_epochs SET generation=1 WHERE tenant_id=$1::uuid`, f.scope.TenantID); err != nil {
						t.Error(err)
					}
				}()
			case "expired-input":
				if _, err := admin.Exec(ctx, `UPDATE flow_conversation_messages SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, f.scope.TenantID, input.input.scope.MessageID); err != nil {
					t.Fatal(err)
				}
			case "paired-rotation":
				replacement, err := f.codec.Rewrap(ctx, input.input.scope, input.input.sealed, check)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(ctx, `UPDATE flow_conversation_messages SET private_header=$3,private_payload=$4 WHERE tenant_id=$1::uuid AND message_id=$2::uuid`, f.scope.TenantID, input.input.scope.MessageID, replacement.parts.header, replacement.parts.payload); err != nil {
					t.Fatal(err)
				}
			case "authority":
				check = func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { return ErrMessageDenied }
			}
			result, err := w.PublishProposal(ctx, lease, proposal, check)
			if err == nil || result.value != nil {
				t.Fatal("changed state published a proposal", fault, err)
			}
			var artifacts, links int
			if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM flow_conversation_messages WHERE tenant_id=$1::uuid AND message_id=$2::uuid),(SELECT count(*) FROM flow_conversation_jobs WHERE tenant_id=$1::uuid AND proposal_message_id=$2::uuid)`, f.scope.TenantID, proposal.value.scope.MessageID).Scan(&artifacts, &links); err != nil || artifacts != 0 || links != 0 || counts("flow.conversation.proposal") != before {
				t.Fatal("proposal refusal left partial artifact/link/audit", fault, err)
			}
			if fault == "audit" {
				journal.record = original
				if err := w.CheckLease(ctx, lease, authorize); err != nil {
					t.Fatal("audit rollback changed the original lease", err)
				}
				if _, err := w.PublishProposal(ctx, lease, proposal, check); err != nil {
					t.Fatal("healthy retry after audit rollback refused", err)
				}
			}
		})
	}
}
