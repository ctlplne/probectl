// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestIRAttributionStageIsUnlinkableAndAADBound(t *testing.T) {
	privatePEM, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	writer, err := crypto.NewRSAOAEPWrapProviderPEM(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	investigator, err := crypto.NewRSAOAEPKeyProviderPEM(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	const (
		tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		canary = "ir-canary-operator@example.test"
		event  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	attribution := IRAttribution{
		Operator: canary,
		TenantID: tenant,
		Grant:    "grant-a",
		Surface:  "results.latest",
		Consent:  "tenant-approved:admin-a",
		Outcome:  "accessed",
		Reason:   "incident response",
		EventRef: event,
		TS:       time.Unix(1_700_000_000, 0).UTC(),
	}
	plaintext, err := marshalIRAttribution(attribution)
	if err != nil {
		t.Fatal(err)
	}
	aad := irStageAAD(tenant, 41, event)
	first, err := crypto.NewEnvelope(writer).Seal(context.Background(), plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	second, err := crypto.NewEnvelope(writer).Seal(context.Background(), plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, err := first.Encode()
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := second.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(firstRaw, []byte(canary)) || bytes.Contains(secondRaw, []byte(canary)) {
		t.Fatal("plaintext canary appears in sealed sidecar bytes")
	}
	if bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("identical attribution produced linkable ciphertext")
	}
	if _, err := crypto.NewEnvelope(writer).Open(context.Background(), first, aad); !errors.Is(err, crypto.ErrUnwrapUnavailable) {
		t.Fatalf("routine public-only writer opened attribution: %v", err)
	}
	opened, err := crypto.NewEnvelope(investigator).Open(context.Background(), first, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("authorized opener reconstructed different attribution")
	}
	for _, wrongAAD := range [][]byte{
		irStageAAD("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 41, event),
		irStageAAD(tenant, 42, event),
		irStageAAD(tenant, 41, "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
	} {
		if _, err := crypto.NewEnvelope(investigator).Open(
			context.Background(),
			first,
			wrongAAD,
		); err == nil {
			t.Fatal("transplanted IR attribution opened under different AAD")
		}
	}
}

func TestIRAttributionRejectsSemanticMismatch(t *testing.T) {
	base := IRAttribution{
		Operator: "operator-id",
		TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Grant:    "grant-a",
		Surface:  "results.latest",
		Consent:  "tenant-approved:admin-a",
		Outcome:  "accessed",
		Reason:   "incident response",
	}
	data := map[string]any{
		"tenant": base.TenantID, "surface": base.Surface, "reason": base.Reason,
	}
	if err := validateIRAttribution(
		"operator@example.test",
		"provider.breakglass_access",
		base.Grant,
		data,
		base,
	); err != nil {
		t.Fatalf("valid attribution rejected: %v", err)
	}
	wrong := base
	wrong.Grant = "grant-b"
	if err := validateIRAttribution(
		"operator@example.test",
		"provider.breakglass_access",
		base.Grant,
		data,
		wrong,
	); err == nil {
		t.Fatal("grant mismatch accepted")
	}
	wrong = base
	wrong.TenantID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if err := validateIRAttribution(
		"operator@example.test",
		"provider.breakglass_access",
		base.Grant,
		data,
		wrong,
	); err == nil {
		t.Fatal("tenant mismatch accepted")
	}
	wrong = base
	wrong.Reason = "different incident"
	if err := validateIRAttribution(
		"operator@example.test",
		"provider.breakglass_access",
		base.Grant,
		data,
		wrong,
	); err == nil {
		t.Fatal("reason mismatch accepted")
	}
	if err := validateIRAttribution(
		"operator@example.test",
		"provider.breakglass_future_action",
		base.Grant,
		data,
		base,
	); err == nil {
		t.Fatal("unmapped protected action accepted")
	}
}

func TestLocalIRPublicKeyResolverLoadsOnlyTenantPublicKey(t *testing.T) {
	tenant := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	privatePEM, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(directory, tenant+".pem"),
		publicPEM,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewLocalIRPublicKeyResolver(directory)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := resolver.WrapProviderForTenant(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	investigator, err := crypto.NewRSAOAEPKeyProviderPEM(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if writer.KeyID() != investigator.KeyID() {
		t.Fatalf("resolved public key id = %q, want %q", writer.KeyID(), investigator.KeyID())
	}
	wrapped, err := writer.WrapKey(context.Background(), bytes.Repeat([]byte{7}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.UnwrapKey(
		context.Background(),
		writer.KeyID(),
		wrapped,
	); !errors.Is(err, crypto.ErrUnwrapUnavailable) {
		t.Fatalf("routine resolver exposed an opener: %v", err)
	}
	for _, invalidTenant := range []string{
		"../" + tenant,
		tenant + ".pem",
		"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
	} {
		if _, err := resolver.WrapProviderForTenant(
			context.Background(),
			invalidTenant,
		); err == nil {
			t.Fatalf("unsafe tenant key path %q was accepted", invalidTenant)
		}
	}
}
