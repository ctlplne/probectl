// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

func TestMessageCodecRewrapPreservesExactSourceOriginAndRequirements(t *testing.T) {
	f := newMessageCodecFixture(t)
	body := []byte("{\n  \"question\": \"bob@example.test \\ud83d\\ude00\", \"number\": 18446744073709551617, \"zero\": -0.000 }\n")
	record := f.seal(t, body)
	old := *record.parts
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	clear(key)
	const keyID = "history-rotation-new"
	ring, err := tenantcrypto.NewEnvelopeKeyringSealer(keyID, encoded, map[string]string{"owned-history-test": f.key})
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(ring)
	baseOpen, baseSeal := f.codec.open, f.codec.seal
	var opened, sealed [][]byte
	f.codec.open = func(ctx context.Context, tenant, stored string, aad []byte) ([]byte, error) {
		plain, err := baseOpen(ctx, tenant, stored, aad)
		opened = append(opened, plain)
		return plain, err
	}
	f.codec.seal = func(ctx context.Context, tenant string, plain, aad []byte) (string, error) {
		sealed = append(sealed, plain)
		return baseSeal(ctx, tenant, plain, aad)
	}
	calls := 0
	replacement, err := f.codec.Rewrap(f.context, f.scope, record, func(ctx context.Context, scope MessageScope, origin auth.WorkerCredentialRef, required []string) error {
		calls++
		if err := f.authorize(ctx, scope, origin, required); err != nil {
			return err
		}
		// A port's scratch use must never weaken the immutable header or the
		// independent second maintenance check.
		clear(required)
		return nil
	})
	if err != nil || replacement.parts == nil || calls != 2 {
		t.Fatal("authorized paired rotation failed", err, calls)
	}
	if *record.parts != old || replacement.parts == record.parts || replacement.parts.header == old.header || replacement.parts.payload == old.payload {
		t.Fatal("rotation mutated the original or reused an old envelope")
	}
	for _, value := range []string{replacement.parts.header, replacement.parts.payload} {
		if got, ok := tenantcrypto.DeploymentEnvelopeKeyID(value); !ok || got != keyID {
			t.Fatal("rotation did not replace both deployment envelopes")
		}
	}
	if len(opened) != 2 || len(sealed) != 2 {
		t.Fatal("unexpected source/header crypto work")
	}
	for _, plain := range append(opened, sealed...) {
		if !bytes.Equal(plain, make([]byte, len(plain))) {
			t.Fatal("rotation retained source or private header scratch bytes")
		}
	}
	f.codec.open, f.codec.seal = baseOpen, baseSeal
	current, err := tenantcrypto.NewEnvelopeSealer(keyID, encoded)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(current)
	got, err := f.codec.Open(f.context, f.scope, replacement, f.authorize)
	defer clear(got)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("rotated source/provenance requires the retired key or changed exact JSON", err)
	}
	if got, err := f.codec.Open(f.context, f.scope, record, f.authorize); got != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("retired original pair opened without its old key", err)
	}
	tenantcrypto.SetPrimary(f.sealer)
	unchanged, err := f.codec.Open(f.context, f.scope, record, f.authorize)
	defer clear(unchanged)
	if err != nil || !bytes.Equal(unchanged, body) {
		t.Fatal("original pair was not retained intact", err)
	}
}

func TestMessageCodecRewrapFailuresNeverPublishHalfPairOrMutateOriginal(t *testing.T) {
	for _, fault := range []string{"denied-before-open", "denied-after-seal", "payload-seal", "header-seal", "keyless-primary", "cancel-before-open", "cancel-payload-seal", "cancel-header-seal", "cancel-final-authority", "stored-budget"} {
		t.Run(fault, func(t *testing.T) {
			f := newMessageCodecFixture(t)
			body := []byte(`{"question":"retained private original"}`)
			record := f.seal(t, body)
			old := *record.parts
			ctx, cancel := context.WithCancel(f.context)
			defer cancel()
			baseOpen, baseSeal := f.codec.open, f.codec.seal
			opens, seals, checks := 0, 0, 0
			var scratch [][]byte
			privateError := errors.New("private backend details must be sanitized")
			f.codec.open = func(ctx context.Context, tenant, stored string, aad []byte) ([]byte, error) {
				plain, err := baseOpen(ctx, tenant, stored, aad)
				scratch = append(scratch, plain)
				if stored == old.payload {
					opens++
					if fault == "keyless-primary" {
						tenantcrypto.SetPrimary(nil)
					}
					if fault == "stored-budget" {
						f.codec.budget.StoredBytes = 1
					}
				}
				return plain, err
			}
			f.codec.seal = func(ctx context.Context, tenant string, plain, aad []byte) (string, error) {
				seals++
				scratch = append(scratch, plain)
				if fault == "payload-seal" && seals == 1 || fault == "header-seal" && seals == 2 {
					return "", privateError
				}
				value, err := baseSeal(ctx, tenant, plain, aad)
				if fault == "cancel-payload-seal" && seals == 1 || fault == "cancel-header-seal" && seals == 2 {
					cancel()
				}
				return value, err
			}
			wantErr := ErrMessageUnavailable
			if fault == "denied-before-open" || fault == "denied-after-seal" {
				wantErr = ErrMessageDenied
			}
			if fault == "stored-budget" {
				wantErr = ErrMessageBudget
			}
			if fault == "cancel-before-open" || fault == "cancel-payload-seal" || fault == "cancel-header-seal" || fault == "cancel-final-authority" {
				wantErr = context.Canceled
			}
			replacement, err := f.codec.Rewrap(ctx, f.scope, record, func(ctx context.Context, scope MessageScope, origin auth.WorkerCredentialRef, required []string) error {
				checks++
				if err := f.authorize(ctx, scope, origin, required); err != nil {
					return err
				}
				if fault == "denied-before-open" || fault == "denied-after-seal" && checks == 2 {
					return privateError
				}
				if fault == "cancel-before-open" || fault == "cancel-final-authority" && checks == 2 {
					cancel()
				}
				return nil
			})
			if replacement.parts != nil || !errors.Is(err, wantErr) || *record.parts != old {
				t.Fatal("failed rotation published a partial pair, changed original or exposed backend detail", err)
			}
			if (fault == "denied-before-open" || fault == "cancel-before-open") && (opens != 0 || seals != 0) {
				t.Fatal("refused current maintenance authority decrypted or rotated source")
			}
			if fault == "denied-after-seal" && (checks != 2 || seals != 2) {
				t.Fatal("final-authority refusal was not exercised after both envelopes")
			}
			for _, plain := range scratch {
				if !bytes.Equal(plain, make([]byte, len(plain))) {
					t.Fatal("failed rotation retained private scratch bytes")
				}
			}
			f.codec.open, f.codec.seal = baseOpen, baseSeal
			f.codec.budget = DefaultCodecBudget()
			tenantcrypto.SetPrimary(f.sealer)
			got, err := f.codec.Open(f.context, f.scope, record, f.authorize)
			defer clear(got)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("failed rotation damaged the old usable pair", err)
			}
		})
	}
}

func TestMessageCodecRewrapMissingAuthorityAndScopeRefuseBeforeCrypto(t *testing.T) {
	f := newMessageCodecFixture(t)
	record := f.seal(t, []byte(`{"q":"private"}`))
	foreign, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	f.codec.open = func(context.Context, string, string, []byte) ([]byte, error) {
		t.Fatal("invalid rotation scope reached crypto")
		return nil, ErrMessageIntegrity
	}
	for _, change := range []func(*MessageScope){
		func(s *MessageScope) { s.TenantID = foreign },
		func(s *MessageScope) { s.OwnerID = "invalid" },
		func(s *MessageScope) { s.Revision = 0 },
		func(s *MessageScope) { s.Epoch = 0 },
	} {
		scope := f.scope
		change(&scope)
		if got, err := f.codec.Rewrap(f.context, scope, record, f.authorize); got.parts != nil || !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("invalid immutable rotation scope accepted", err)
		}
	}
	for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(f.context, tenancy.ID(foreign))} {
		if got, err := f.codec.Rewrap(ctx, f.scope, record, f.authorize); got.parts != nil || !errors.Is(err, ErrMessageIntegrity) {
			t.Fatal("rotation accepted absent or foreign ambient tenant", err)
		}
	}
	if got, err := f.codec.Rewrap(f.context, f.scope, record, nil); got.parts != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("rotation accepted missing current maintenance authority", err)
	}
	if got, err := f.codec.Rewrap(f.context, f.scope, SealedMessage{}, f.authorize); got.parts != nil || !errors.Is(err, ErrMessageIntegrity) {
		t.Fatal("rotation accepted an empty record", err)
	}
}

func TestMessageCodecRewrapSameScopePairSwapRefusesBeforeAuthority(t *testing.T) {
	f := newMessageCodecFixture(t)
	a := f.seal(t, []byte(`{"q":"first"}`))
	b := f.seal(t, []byte(`{"q":"second"}`))
	for _, pair := range []sealedMessageParts{{header: a.parts.header, payload: b.parts.payload}, {header: b.parts.header, payload: a.parts.payload}} {
		calls := 0
		if got, err := f.codec.Rewrap(f.context, f.scope, SealedMessage{&pair}, func(context.Context, MessageScope, auth.WorkerCredentialRef, []string) error { calls++; return nil }); got.parts != nil || !errors.Is(err, ErrMessageIntegrity) || calls != 0 {
			t.Fatal("rotation blessed a swapped header/payload pair", err)
		}
	}
}
