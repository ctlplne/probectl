// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

func TestSubjectPlanCanonicalPrivateEncryptedRoundTrip(t *testing.T) {
	f := newMessageCodecFixture(t)
	aliases := []string{" USER@EXAMPLE.TEST ", f.scope.OwnerID, "user@example.test"}
	plan, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, " User@Example.Test ", aliases)
	if err != nil {
		t.Fatal(err)
	}
	aliases[0] = "changed@directory.test"
	stored, err := f.codec.sealSubjectPlan(f.context, plan)
	if err != nil || strings.Contains(stored, "example.test") {
		t.Fatal("plan was not privately sealed", err)
	}
	opened, err := f.codec.openSubjectPlan(f.context, plan.value.request, stored)
	if err != nil || opened.value.wire.Subject != "User@Example.Test" || !slices.Equal(opened.value.wire.Aliases, plan.value.wire.Aliases) || slices.Contains(opened.value.wire.Aliases, aliases[0]) {
		t.Fatal("selector changed after canonical encrypted round trip", err)
	}
	second, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, "User@Example.Test", plan.value.wire.Aliases)
	if err != nil || second.value.request.Binding == plan.value.request.Binding {
		t.Fatal("independent plan did not receive a fresh private salt", err)
	}
	if _, err := json.Marshal(plan); !errors.Is(err, errMessagePrivate) {
		t.Fatal("plan crossed JSON boundary", err)
	}
	if err := json.Unmarshal([]byte(`{}`), new(SubjectErasurePlan)); !errors.Is(err, errMessagePrivate) {
		t.Fatal("JSON fabricated a plan", err)
	}
	if shown := fmt.Sprintf("%#v", plan); strings.Contains(shown, "Example") || strings.Contains(shown, f.scope.TenantID) || strings.Contains(shown, f.credentialID) {
		t.Fatal("formatting leaked the plan")
	}
	for _, mutate := range []func(*MaintenanceRequest){
		func(r *MaintenanceRequest) { r.ID = f.scope.MessageID },
		func(r *MaintenanceRequest) { r.Binding[0] ^= 1 },
		func(r *MaintenanceRequest) { r.Kind = MaintenanceRetention },
	} {
		request := plan.value.request
		mutate(&request)
		if got, err := f.codec.openSubjectPlan(f.context, request, stored); got.value != nil || !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("changed purpose/operation/binding opened the plan", err)
		}
	}
	foreign := tenancy.WithTenant(f.context, tenancy.ID(f.scope.MessageID))
	if got, err := f.codec.openSubjectPlan(foreign, plan.value.request, stored); got.value != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("plan replayed across tenant boundary", err)
	}
	tenantcrypto.Reset()
	if got, err := f.codec.sealSubjectPlan(f.context, plan); got != "" || !errors.Is(err, ErrMessageUnavailable) {
		t.Fatal("keyless plan was stored as plaintext", err)
	}
	if got, err := f.codec.openSubjectPlan(f.context, plan.value.request, stored); got.value != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("unavailable key opened the plan", err)
	}
}

func TestSubjectPlanRejectsInvalidDocumentsResourcesAndAuthority(t *testing.T) {
	f := newMessageCodecFixture(t)
	for _, subject := range []string{"", "  ", string([]byte{0xff})} {
		if got, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, subject, nil); got.value != nil || !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid subject admitted", err)
		}
	}
	for _, aliases := range [][]string{{""}, {"  "}, {string([]byte{0xff})}} {
		if got, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, "valid@example.test", aliases); got.value != nil || !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid alias admitted", err)
		}
	}
	small, err := NewCodec(CodecBudget{PlainBytes: 128, HeaderBytes: 128, StoredBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := small.PrepareSubjectErasurePlan(f.context, f.credentialID, "valid@example.test", []string{strings.Repeat("x", 128)}); got.value != nil || !errors.Is(err, ErrMessageBudget) {
		t.Fatal("unbounded alias input admitted", err)
	}
	plan, err := f.codec.PrepareSubjectErasurePlan(f.context, f.credentialID, "valid@example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.codec.sealSubjectPlan(f.context, plan)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := small.openSubjectPlan(f.context, plan.value.request, stored); got.value != nil || !errors.Is(err, ErrMessageBudget) {
		t.Fatal("oversized stored plan admitted", err)
	}
	// Correct AEAD with a digest covering noncanonical JSON is still refused.
	body, err := json.Marshal(plan.value.wire)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	noncanonical := append([]byte(" "), body...)
	defer clear(noncanonical)
	request := plan.value.request
	request.Binding = bindingArray(crypto.Hash(noncanonical))
	bad, err := tenantcrypto.Seal(f.context, plan.value.tenant, noncanonical, subjectPlanAAD(plan.value.tenant, request))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.codec.openSubjectPlan(f.context, request, bad); got.value != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("noncanonical encrypted plan admitted", err)
	}
	var journal *Journal
	denied := func(context.Context, string) error { return errors.New("revoked") }
	if got, err := journal.BeginSubjectInvalidation(f.context, f.codec, plan, denied); got.value != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("revoked authority reached plan storage", err)
	}
	if pending, got, err := journal.ResumeSubjectInvalidation(f.context, f.codec, f.credentialID, denied); pending.value != nil || got.value != nil || !errors.Is(err, ErrMessageDenied) {
		t.Fatal("revoked authority resumed plan storage", err)
	}
}
