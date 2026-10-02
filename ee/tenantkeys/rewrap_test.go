// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package tenantkeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// CRY-02: a managed tenant KEK sealed under the deployment key A must survive a
// documented envelope rotation to active key B (with A kept as an opener, the
// way ee_attach now builds the master), and envelope-rewrap must then re-seal it
// under B so A can be fully retired.
func TestManagedKEKSurvivesRotationAndRewrap(t *testing.T) {
	ctx := context.Background()
	b64 := func(n int) string {
		k, err := crypto.Random(n)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(k)
	}
	keyA, keyB := b64(32), b64(32)

	master := func(active, b64key string, openers map[string]string) *crypto.Envelope {
		kp, err := crypto.NewStaticKeyProviderFromBase64Keyring(active, b64key, openers)
		if err != nil {
			t.Fatal(err)
		}
		return crypto.NewEnvelope(kp)
	}
	masterA := master("A", keyA, nil)                          // original deployment key
	masterB := master("B", keyB, map[string]string{"A": keyA}) // rotated: active B + opener A (the fix)
	masterBNoOpener := master("B", keyB, nil)                  // the pre-fix wiring (bricks)

	mem := newMemStore()
	tenant, version := "t-1", 1
	aad := []byte("tenant-kek:" + tenant + ":" + strconv.Itoa(version))
	kek, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := masterA.Seal(ctx, kek, aad)
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.Insert(ctx, KeyVersion{
		TenantID: tenant, Version: version, Mode: ModeManaged, State: StateActive,
		WrappedKEK: encodeSealed(sealed), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// The brick this fixes: without the retired key as an opener, the rotated
	// master cannot unwrap the value sealed under A.
	if _, err := masterBNoOpener.Open(ctx, sealed, aad); err == nil {
		t.Fatal("openerless rotated master unexpectedly opened the retired-key value (brick not reproduced)")
	}
	// With A as an opener (the fix), the rotated master opens it cleanly.
	got, err := masterB.Open(ctx, sealed, aad)
	if err != nil {
		t.Fatalf("opener-aware rotated master must open the retired-key value: %v", err)
	}
	if !bytes.Equal(got, kek) {
		t.Fatal("unwrapped KEK does not match the original")
	}

	// Rewrap A -> B.
	stats, err := RewrapManagedKEKs(ctx, masterB, mem, "B", "A", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Matched != 1 || stats.Rewrapped != 1 {
		t.Fatalf("rewrap stats = %+v, want matched=1 rewrapped=1", stats)
	}
	// The stored value is now under B and opens with the active key ALONE — A is
	// no longer needed, so the operator can retire it.
	chain, err := mem.Chain(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := decodeSealed(chain[0].WrappedKEK)
	if err != nil {
		t.Fatal(err)
	}
	if s2.KeyID != "B" {
		t.Fatalf("rewrapped key id = %q, want B", s2.KeyID)
	}
	if _, err := masterBNoOpener.Open(ctx, s2, aad); err != nil {
		t.Fatalf("after rewrap the value must open under the active key with no opener: %v", err)
	}

	// --verify-retired-key-id A: zero values remain under A, and the active value verifies.
	vstats, err := RewrapManagedKEKs(ctx, masterB, mem, "B", "A", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if vstats.Matched != 0 {
		t.Fatalf("verify: %d value(s) still under retired key A, want 0", vstats.Matched)
	}
	if vstats.Verified != 1 {
		t.Fatalf("verify: %d active value(s) opened, want 1", vstats.Verified)
	}
}
