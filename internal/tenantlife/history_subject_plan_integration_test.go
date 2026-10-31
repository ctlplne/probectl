// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/flowconversation"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

func directoryPlanUser(t *testing.T, admin *pgxpool.Pool, tenant, email string) string {
	t.Helper()
	id := historyEraseUUID(t)
	if _, err := admin.Exec(t.Context(), `INSERT INTO users(id,tenant_id,email,display_name,status,user_name,attributes) VALUES($1::uuid,$2::uuid,$3,'Owned directory plan','active',$3,'{}')`, id, tenant, email); err != nil {
		t.Fatal(err)
	}
	return id
}

func directoryPlanSession(t *testing.T, admin *pgxpool.Pool, tenant, user, email string) string {
	t.Helper()
	id := historyEraseUUID(t)
	hash, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(hash)
	if _, err := admin.Exec(t.Context(), `INSERT INTO sessions(id,tenant_id,user_id,email,token_hash,expires_at) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,clock_timestamp()+interval '1 hour')`, id, tenant, user, email, hash); err != nil {
		t.Fatal(err)
	}
	return id
}

func directoryPlanCrypto(t *testing.T) {
	t.Helper()
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("owned-directory-plan", base64.StdEncoding.EncodeToString(key))
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
}

func directoryPlanCurrent(ctx context.Context, tenant string) error {
	id, ok := tenancy.FromContext(ctx)
	if !ok || id.String() != tenant {
		return flowconversation.ErrMessageDenied
	}
	return ctx.Err()
}

func directoryPlanEpoch(t *testing.T, admin *pgxpool.Pool, tenant string) (int64, bool, int) {
	t.Helper()
	var epoch int64
	var pending bool
	var events int
	if err := admin.QueryRow(t.Context(), `SELECT COALESCE((SELECT generation FROM flow_conversation_epochs WHERE tenant_id=$1::uuid),0),COALESCE((SELECT invalidating FROM flow_conversation_epochs WHERE tenant_id=$1::uuid),false),(SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.conversation.invalidate_intent')`, tenant).Scan(&epoch, &pending, &events); err != nil {
		t.Fatal(err)
	}
	return epoch, pending, events
}

func TestHistorySubjectPlanPostgresStableIdentityAndRestart(t *testing.T) {
	admin, pool, red, blue := historyEraseFixture(t)
	directoryPlanCrypto(t)
	engine := New(pool, nil, nil, nil, nil, "owned directory fixtures", testLog())
	email := "subject-plan@example.test"
	user := directoryPlanUser(t, admin, red, email)
	blueUser := directoryPlanUser(t, admin, blue, email)
	owned := directoryPlanSession(t, admin, red, user, email)
	directoryPlanSession(t, admin, blue, blueUser, email)
	bystander := directoryPlanUser(t, admin, red, "bystander@example.test")
	stale := directoryPlanSession(t, admin, red, bystander, email)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(red))
	op := historyEraseUUID(t)
	prepared, err := engine.prepareHistorySubject(ctx, red, op, email, flowconversation.DefaultCodecBudget(), directoryPlanCurrent)
	if err != nil {
		t.Fatal("typed directory preparation refused", err)
	}
	defer prepared.release()
	if prepared.snapshot.value.Kind != "user" || prepared.snapshot.value.ID != user || !slices.Equal(prepared.snapshot.value.SessionIDs, []string{owned}) || slices.Contains(prepared.snapshot.value.Aliases, stale) {
		t.Fatal("stable identity adopted another user's stale session email")
	}
	if _, err := engine.beginPreparedHistorySubject(ctx, prepared, directoryPlanCurrent); err != nil {
		t.Fatal("atomic typed approval refused", err)
	}
	if epoch, pending, events := directoryPlanEpoch(t, admin, red); epoch != 2 || !pending || events != 1 {
		t.Fatal("approval lacked its exact marker/epoch/audit", epoch, pending, events)
	}
	var leaked bool
	if err := admin.QueryRow(t.Context(), `SELECT operation_plan LIKE '%example.test%' OR operation_plan LIKE '%'||$2||'%' FROM flow_conversation_epochs WHERE tenant_id=$1::uuid`, red, user).Scan(&leaked); err != nil || leaked {
		t.Fatal("directory snapshot entered storage without encryption", err)
	}
	// Rename original identity and add a new credential. Resume must follow
	// that UUID without rewriting its approved initial alias/locator snapshot.
	if _, err := admin.Exec(t.Context(), `UPDATE users SET email='renamed@example.test',user_name='renamed@example.test' WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, user); err != nil {
		t.Fatal(err)
	}
	newSession := directoryPlanSession(t, admin, red, user, "renamed@example.test")
	restarted := New(pool, nil, nil, nil, nil, "owned restart", testLog())
	_, frozen, current, err := restarted.resumeHistorySubject(ctx, red, op, flowconversation.DefaultCodecBudget(), directoryPlanCurrent)
	if err != nil || frozen.value.ID != user || !slices.Equal(frozen.value.SessionIDs, []string{owned}) || !current.present || !slices.Contains(current.sessionIDs, newSession) || !slices.Contains(current.directoryAliases, "renamed@example.test") || slices.Contains(current.sessionIDs, stale) {
		t.Fatal("restart re-resolved aliases or lost same-ID credentials", err)
	}
	frozen.release()
	// Once the old alias is assigned to a replacement, refuse instead of
	// silently adopting/deleting the replacement or clearing the intent.
	replacement := directoryPlanUser(t, admin, red, email)
	if _, snapshot, _, err := restarted.resumeHistorySubject(ctx, red, op, flowconversation.DefaultCodecBudget(), directoryPlanCurrent); !errors.Is(err, flowconversation.ErrJournalConflict) || snapshot.value != nil {
		t.Fatal("old alias silently selected replacement identity", err)
	}
	var users int
	if err := admin.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE id=ANY($1::uuid[])`, []string{user, replacement, blueUser}).Scan(&users); err != nil || users != 3 {
		t.Fatal("directory reconciliation mutated original/replacement/sibling", err)
	}
}

func TestHistorySubjectPlanPostgresApprovalRefusalsAndAbsentIdentity(t *testing.T) {
	for _, fault := range []string{"transfer_before_approval", "projection_drift", "credential_drift", "audit_failure", "missing_validator", "literal_adoption", "identity_absent", "service_account", "revoked_resume", "directory_force_missing"} {
		t.Run(fault, func(t *testing.T) {
			admin, pool, red, blue := historyEraseFixture(t)
			directoryPlanCrypto(t)
			engine := New(pool, nil, nil, nil, nil, "owned directory fixtures", testLog())
			email := "approval@example.test"
			user := ""
			if fault == "service_account" {
				user = historyEraseUUID(t)
				if _, err := admin.Exec(t.Context(), `INSERT INTO service_accounts(id,tenant_id,name)VALUES($1::uuid,$2::uuid,$3)`, user, red, email); err != nil {
					t.Fatal(err)
				}
			} else if fault != "literal_adoption" {
				user = directoryPlanUser(t, admin, red, email)
			}
			blueUser := directoryPlanUser(t, admin, blue, email)
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(red))
			op := historyEraseUUID(t)
			prepared, err := engine.prepareHistorySubject(ctx, red, op, email, flowconversation.DefaultCodecBudget(), directoryPlanCurrent)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.release()
			expectApproval := fault == "literal_adoption" || fault == "identity_absent" || fault == "service_account" || fault == "revoked_resume"
			switch fault {
			case "transfer_before_approval", "projection_drift":
				if _, err := admin.Exec(t.Context(), `UPDATE users SET email='moved@example.test',user_name='moved@example.test' WHERE id=$1::uuid`, user); err != nil {
					t.Fatal(err)
				}
				replacement := directoryPlanUser(t, admin, red, email)
				if fault == "projection_drift" {
					// The mutable preparation projection cannot replace the
					// already encoded immutable approval application.
					prepared.snapshot.value.ID = replacement
					prepared.snapshot.value.DirectoryAliases = []string{replacement, email}
					slices.Sort(prepared.snapshot.value.DirectoryAliases)
					prepared.snapshot.value.Aliases = slices.Clone(prepared.snapshot.value.DirectoryAliases)
				}
			case "credential_drift":
				directoryPlanSession(t, admin, red, user, email)
			case "audit_failure":
				if _, err := admin.Exec(t.Context(), `REVOKE INSERT ON audit_events FROM probectl_app`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := admin.Exec(context.Background(), `GRANT INSERT ON audit_events TO probectl_app`); err != nil {
						t.Error("owned audit privilege restore failed", err)
					}
				}()
			case "directory_force_missing":
				if _, err := admin.Exec(t.Context(), `ALTER TABLE users NO FORCE ROW LEVEL SECURITY`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := admin.Exec(context.Background(), `ALTER TABLE users FORCE ROW LEVEL SECURITY`); err != nil {
						t.Error("owned directory posture restore failed", err)
					}
				}()
			}
			if fault == "missing_validator" {
				_, err = flowconversation.NewJournal(pool).BeginSubjectInvalidation(ctx, prepared.codec, prepared.plan, directoryPlanCurrent)
			} else {
				_, err = engine.beginPreparedHistorySubject(ctx, prepared, directoryPlanCurrent)
			}
			if !expectApproval {
				if err == nil {
					t.Fatal("changed/invalid approval committed")
				}
				if epoch, pending, events := directoryPlanEpoch(t, admin, red); epoch != 0 || pending || events != 0 {
					t.Fatal("failed application validation changed marker/epoch/audit", epoch, pending, events)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			current := flowconversation.AuthorizeMaintenance(directoryPlanCurrent)
			want := error(nil)
			switch fault {
			case "literal_adoption":
				directoryPlanUser(t, admin, red, email)
				want = flowconversation.ErrJournalConflict
			case "identity_absent":
				if _, err := admin.Exec(t.Context(), `DELETE FROM users WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, user); err != nil {
					t.Fatal(err)
				}
			case "revoked_resume":
				current = func(context.Context, string) error { return flowconversation.ErrMessageDenied }
				want = flowconversation.ErrMessageDenied
			}
			_, snapshot, state, err := engine.resumeHistorySubject(ctx, red, op, flowconversation.DefaultCodecBudget(), current)
			defer snapshot.release()
			if want != nil {
				if !errors.Is(err, want) || snapshot.value != nil {
					t.Fatal("unknown/new directory identity was adopted", err)
				}
			} else if err != nil || snapshot.value.ID != user || fault == "identity_absent" && state.present || fault == "service_account" && (snapshot.value.Kind != "service_account" || !state.present) {
				t.Fatal("stable typed identity reconciliation failed", err)
			}
			var siblings int
			if err := admin.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE tenant_id=$1::uuid AND id=$2::uuid`, blue, blueUser).Scan(&siblings); err != nil || siblings != 1 {
				t.Fatal("directory approval/restart changed sibling", err)
			}
		})
	}
}
