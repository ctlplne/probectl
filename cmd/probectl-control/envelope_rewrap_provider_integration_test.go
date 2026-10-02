// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/ee/provider"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
)

// TestEnvelopeRewrapRotatesProviderOperatorTOTP is the PLAT-04 reopen
// regression. provider_operators.totp_* (operator MFA) is sealed with the same
// deployment envelope as alert_rules/tenant_idp/agent_ca, but the rewrap command
// did not walk it: verify-retired falsely succeeded and retiring the old KEK
// locked every provider operator out of the console. After the fix the rewrap
// set includes provider operator TOTP: execute rewraps it, verify fails closed
// while it carries the retired id, and the secret still opens under the
// new-only keyring once the opener is gone.
func TestEnvelopeRewrapRotatesProviderOperatorTOTP(t *testing.T) {
	db := setupEnvelopeRewrapDB(t)
	ctx := context.Background()
	oldKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32))
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	const oldID, newID = "old-plat04b", "new-plat04b"

	st := provider.NewPGStore(db.Pool())
	email := fmt.Sprintf("plat04b-%d@msp.example", time.Now().UnixNano())
	op, err := st.CreateOperator(ctx, provider.Operator{Email: email, Name: "PLAT-04b", Role: provider.RoleAdmin}, crypto.Hash([]byte(email)))
	if err != nil {
		t.Fatalf("create operator: %v", err)
	}
	aad := []byte("provider-totp:" + op.ID)
	secret := []byte("plat04b-totp-seed")

	// Seal the operator's TOTP under the OLD deployment key, as a pre-rotation
	// deployment would have.
	oldKP, err := crypto.NewStaticKeyProviderFromBase64(oldID, oldKey)
	if err != nil {
		t.Fatalf("old key: %v", err)
	}
	sealedOld, err := crypto.NewEnvelope(oldKP).Seal(ctx, secret, aad)
	if err != nil {
		t.Fatalf("seal totp under old key: %v", err)
	}
	if err := st.SetOperatorTOTP(ctx, op.ID, sealedOld); err != nil {
		t.Fatalf("set totp: %v", err)
	}

	totpKeyID := func(t *testing.T) string {
		t.Helper()
		var id string
		if err := db.Pool().QueryRow(ctx, `SELECT totp_key_id FROM provider_operators WHERE id = $1::uuid`, op.ID).Scan(&id); err != nil {
			t.Fatalf("read totp_key_id: %v", err)
		}
		return id
	}
	if totpKeyID(t) != oldID {
		t.Fatalf("precondition: operator TOTP should be sealed under %s", oldID)
	}

	cfg := &config.Config{EnvelopeKeyID: newID, EnvelopeKey: newKey, EnvelopeOpenerKeys: oldID + "=" + oldKey}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// (A) verify-retired must FAIL CLOSED while the provider TOTP still uses the
	// retired key. Pre-fix this returned success (provider_operators unscanned).
	if err := runEnvelopeRewrap(ctx, cfg, db, log, []string{"--verify-retired-key-id=" + oldID}); err == nil || !strings.Contains(err.Error(), oldID) {
		t.Fatalf("PLAT-04: verify-retired must fail closed while provider TOTP carries the retired key, got %v", err)
	}

	// (B) execute rewrap must move the provider TOTP onto the active key.
	if err := runEnvelopeRewrap(ctx, cfg, db, log, []string{"--from-key-id=" + oldID}); err != nil {
		t.Fatalf("execute rewrap: %v", err)
	}
	if got := totpKeyID(t); got != newID {
		t.Fatalf("PLAT-04: provider TOTP still sealed under %q after rewrap (want %s)", got, newID)
	}

	// (C) remove the retired opener; verify-retired must now pass AND the operator
	// TOTP must still decrypt under the new-only key (no console lockout).
	if err := runEnvelopeRewrap(ctx, &config.Config{EnvelopeKeyID: newID, EnvelopeKey: newKey}, db, log, []string{"--verify-retired-key-id=" + oldID}); err != nil {
		t.Fatalf("verify after rewrap + opener removal: %v", err)
	}
	_, cred, err := st.OperatorByEmail(ctx, email)
	if err != nil {
		t.Fatalf("read operator after rotation: %v", err)
	}
	newOnly, err := crypto.NewStaticKeyProviderFromBase64(newID, newKey)
	if err != nil {
		t.Fatalf("new-only key: %v", err)
	}
	opened, err := crypto.NewEnvelope(newOnly).Open(ctx, cred.TOTP, aad)
	if err != nil {
		t.Fatalf("PLAT-04: provider operator TOTP cannot be opened after retiring the old key (console lockout): %v", err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatalf("PLAT-04: decrypted TOTP mismatch after rotation")
	}
}
