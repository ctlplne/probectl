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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestHistoryJournalPostgresEncryptedSubjectPlanRestartAndRefusals(t *testing.T) {
	admin, pool := journalFixture(t)
	if admin == nil {
		return
	}
	f := newMessageCodecFixture(t)
	red, blue := f.scope.TenantID, mustInvalidationUUID(t)
	for _, tenant := range []string{red, blue} {
		if _, err := admin.Exec(t.Context(), `INSERT INTO tenants(id,slug,name) VALUES($1::uuid,$2,'Owned subject plan fixture')`, tenant, "probectl-qa-beta-plan-"+strings.ReplaceAll(tenant, "-", "")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
			t.Error("owned subject-plan tenant cleanup failed", err)
		}
	})
	allow := func(ctx context.Context, tenant string) error {
		current, ok := tenancy.FromContext(ctx)
		if !ok || current.String() != red || tenant != red {
			return ErrMessageDenied
		}
		return ctx.Err()
	}
	plan, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, "User@Example.Test", []string{f.scope.OwnerID, "previous@directory.test"})
	if err != nil {
		t.Fatal(err)
	}
	journal := NewJournal(pool)
	original := journal.record
	journal.record = func(context.Context, tenancy.Scope, string, string, string, map[string]any) error {
		return errors.New("owned audit failure")
	}
	if pending, err := journal.BeginSubjectInvalidation(f.context, f.codec, plan, allow); pending.value != nil || !errors.Is(err, ErrJournalUnavailable) {
		t.Fatal("audit failure committed the encrypted intent", err)
	}
	journal.record = original
	var n int
	if err := admin.QueryRow(t.Context(), `SELECT count(*) FROM flow_conversation_epochs WHERE tenant_id=$1::uuid`, red).Scan(&n); err != nil || n != 0 {
		t.Fatal("failed audit retained a plan or advanced generation", err)
	}
	pending, err := journal.BeginSubjectInvalidation(f.context, f.codec, plan, allow)
	if err != nil || pending.value == nil || pending.value.generation != 2 {
		t.Fatal("encrypted intent failed to begin", err)
	}
	var stored, auditData string
	if err := admin.QueryRow(t.Context(), `SELECT operation_plan FROM flow_conversation_epochs WHERE tenant_id=$1::uuid`, red).Scan(&stored); err != nil || strings.Contains(stored, "directory.test") {
		t.Fatal("plan missing or exposed plaintext", err)
	}
	if err := admin.QueryRow(t.Context(), `SELECT data::text FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.conversation.invalidate_intent'`, red).Scan(&auditData); err != nil || strings.Contains(auditData, "directory.test") || strings.Contains(auditData, f.scope.OwnerID) {
		t.Fatal("audit disclosed selector or stable alias", err)
	}
	// A new Journal has no creating process plan or mutable directory state.
	resumed, frozen, err := NewJournal(pool).ResumeSubjectInvalidation(f.context, f.codec, f.credentialID, allow)
	if err != nil || resumed.value == nil || *resumed.value != *pending.value || frozen.value == nil || !slices.Equal(frozen.value.wire.Aliases, plan.value.wire.Aliases) {
		t.Fatal("restart changed the immutable selector", err)
	}
	if retried, err := NewJournal(pool).BeginSubjectInvalidation(f.context, f.codec, frozen, allow); err != nil || retried.value == nil || *retried.value != *pending.value {
		t.Fatal("exact start retry failed", err)
	}
	if err := admin.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND action='flow.conversation.invalidate_intent'`, red).Scan(&n); err != nil || n != 1 {
		t.Fatal("restart duplicated the intent audit", err)
	}
	changed, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, "User@Example.Test", []string{"new@directory.test"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := journal.BeginSubjectInvalidation(f.context, f.codec, changed, allow); got.value != nil || !errors.Is(err, ErrJournalConflict) {
		t.Fatal("changed aliases adopted an existing intent", err)
	}
	deny := func(context.Context, string) error { return errors.New("revoked") }
	if got, frozen, err := journal.ResumeSubjectInvalidation(f.context, f.codec, f.credentialID, deny); got.value != nil || frozen.value != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("revoked privacy authority resumed the plan", err)
	}
	calls := 0
	beforeDecrypt := func(context.Context, string) error {
		calls++
		if calls >= 2 {
			return errors.New("revoked after SQL")
		}
		return nil
	}
	codec := *f.codec
	codec.open = func(context.Context, string, string, []byte) ([]byte, error) {
		t.Error("revoked operation reached decrypt")
		return nil, ErrMessageIntegrity
	}
	if got, frozen, err := journal.ResumeSubjectInvalidation(f.context, &codec, f.credentialID, beforeDecrypt); got.value != nil || frozen.value != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("authority was not rechecked before decrypt", err)
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID(blue))
	if got, frozen, err := journal.ResumeSubjectInvalidation(foreign, f.codec, f.credentialID, func(context.Context, string) error { return nil }); got.value != nil || frozen.value != nil || !errors.Is(err, ErrJournalConflict) {
		t.Fatal("foreign tenant loaded the plan", err)
	}
	if got, frozen, err := journal.ResumeSubjectInvalidation(f.context, f.codec, mustInvalidationUUID(t), allow); got.value != nil || frozen.value != nil || !errors.Is(err, ErrJournalConflict) {
		t.Fatal("wrong operation adopted the plan", err)
	}
	if _, err := journal.CandidateEpoch(f.requestContext(t)); !errors.Is(err, ErrJournalGeneration) {
		t.Fatal("plan resume reopened ordinary source", err)
	}
	sibling := f
	sibling.scope.TenantID = blue
	sibling.context = foreign
	sibling.origin, err = auth.CaptureWorkerCredential(auth.WorkerCredentialMCP, blue, sibling.scope.OwnerID, sibling.credentialID, sibling.storedHash)
	if err != nil {
		t.Fatal(err)
	}
	if generation, err := journal.CandidateEpoch(sibling.requestContext(t)); err != nil || generation != 1 {
		t.Fatal("red intent fenced the healthy sibling", err)
	}
	// Faults are injected only by the fixture administrator. Runtime decrypt
	// must fail closed; the original marker/ciphertext are restored exactly.
	for _, fault := range []string{"ciphertext", "binding", "purpose", "missing"} {
		switch fault {
		case "ciphertext":
			_, err = admin.Exec(t.Context(), `UPDATE flow_conversation_epochs SET operation_plan=$2 WHERE tenant_id=$1::uuid`, red, stored+"x")
		case "binding":
			bad := plan.value.request.Binding
			bad[0] ^= 1
			_, err = admin.Exec(t.Context(), `UPDATE flow_conversation_epochs SET operation_binding=$2 WHERE tenant_id=$1::uuid`, red, bad[:])
		case "purpose":
			_, err = admin.Exec(t.Context(), `UPDATE flow_conversation_epochs SET operation_kind='retention',operation_plan=NULL WHERE tenant_id=$1::uuid`, red)
		case "missing":
			_, err = admin.Exec(t.Context(), `UPDATE flow_conversation_epochs SET operation_plan=NULL WHERE tenant_id=$1::uuid`, red)
		}
		if err != nil {
			t.Fatal(err)
		}
		got, frozen, refusal := journal.ResumeSubjectInvalidation(f.context, f.codec, f.credentialID, allow)
		if got.value != nil || frozen.value != nil || refusal == nil {
			t.Fatal("faulted plan resumed", fault)
		}
		if _, err := admin.Exec(t.Context(), `UPDATE flow_conversation_epochs SET operation_kind='subject_erase',operation_binding=$2,operation_plan=$3 WHERE tenant_id=$1::uuid`, red, plan.value.request.Binding[:], stored); err != nil {
			t.Fatal(err)
		}
	}
	limited := *f.codec
	limited.budget.StoredBytes = 16
	if got, frozen, err := journal.ResumeSubjectInvalidation(f.context, &limited, f.credentialID, allow); got.value != nil || frozen.value != nil || !errors.Is(err, ErrMessageBudget) {
		t.Fatal("oversized plan transferred/decrypted", err)
	}
	if got, frozen, err := NewJournal(pool).ResumeSubjectInvalidation(f.context, f.codec, f.credentialID, allow); err != nil || got.value == nil || frozen.value == nil {
		t.Fatal("refusal corrupted the durable exact plan", err)
	}
}
