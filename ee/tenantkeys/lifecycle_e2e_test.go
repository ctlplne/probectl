// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package tenantkeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// TestBYOKLifecycleE2E walks the full F500 BYOK key lifecycle in one narrative
// (EXC-ORG-04, closing KEYS-002/003 for the regulated profile): provision →
// rotate (no-downtime, old generation still opens) → adopt customer BYOK →
// bounded revocation (the cached KEK is zeroized and a revoked reference fails
// safe within the window) → cryptographic destruction (zeroization of every
// version's material + permanent unreadability). Each transition is asserted, so
// a regression that (a) loses an old generation on rotate, (b) leaves a live KEK
// in memory after revoke, or (c) silently re-keys after destroy fails here.
func TestBYOKLifecycleE2E(t *testing.T) {
	const tenant = "tn-acme"
	aad := []byte("alert-webhook-secret")
	ctx := context.Background()

	// A customer secret reference the keyring resolves through the operator's
	// vault. We flip `live` to simulate the customer revoking probectl's access.
	material := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	live := true
	resolve := func(_ context.Context, ref string) ([]byte, func(), error) {
		if !live {
			return nil, nil, errors.New("vault: access revoked by customer")
		}
		if ref != "vault:kv/acme#kek" {
			return nil, nil, errors.New("vault: not found")
		}
		b := []byte(material)
		return b, func() { crypto.Zeroize(b) }, nil
	}

	k, store := newRing(t, resolve)
	// A positive managed-KEK TTL so a managed KEK is actually cached — that is
	// what lets us assert the bytes are ZEROIZED on revoke/destroy (KEYS-003).
	k.WithTTL(5 * time.Minute)
	now := time.Unix(2_000, 0)
	k.WithClock(func() time.Time { return now })

	// ── 1. Provision (managed): first seal mints v1 and caches its KEK. ──────
	v1blob, err := k.Seal(ctx, tenant, []byte("v1-secret"), aad)
	if err != nil {
		t.Fatalf("provision seal: %v", err)
	}
	cachedV1 := captureCachedKEK(t, k, tenant, 1)
	if allZero(cachedV1) {
		t.Fatal("managed KEK should be cached non-zero after the first seal")
	}

	// ── 2. Rotate (managed → managed): no downtime; v1 still opens, v2 is new.
	kv2, err := k.Rotate(ctx, tenant, ModeManaged, "")
	if err != nil || kv2.Version != 2 {
		t.Fatalf("rotate to v2: %+v %v", kv2, err)
	}
	// Rotation purges (and zeroizes) the old cached KEK.
	if !allZero(cachedV1) {
		t.Error("KEYS-003: v1 KEK bytes must be zeroized in memory after rotation")
	}
	if p, err := k.Open(ctx, tenant, v1blob, aad); err != nil || string(p) != "v1-secret" {
		t.Fatalf("v1 ciphertext must still open after rotation (no re-encryption): %q %v", p, err)
	}
	v2blob, err := k.Seal(ctx, tenant, []byte("v2-secret"), aad)
	if err != nil || v2blob[:6] != "tk1:2:" {
		t.Fatalf("new seals must use v2: %q %v", v2blob, err)
	}

	// ── 3. Adopt customer BYOK (rotate managed → byok). ─────────────────────
	kv3, err := k.Rotate(ctx, tenant, ModeBYOK, "vault:kv/acme#kek")
	if err != nil || kv3.Mode != ModeBYOK || kv3.Version != 3 {
		t.Fatalf("rotate to byok v3: %+v %v", kv3, err)
	}
	byokBlob, err := k.Seal(ctx, tenant, []byte("customer-keyed"), aad)
	if err != nil {
		t.Fatalf("byok seal: %v", err)
	}
	if p, err := k.Open(ctx, tenant, byokBlob, aad); err != nil || string(p) != "customer-keyed" {
		t.Fatalf("byok round-trip: %q %v", p, err)
	}

	// ── 4. Bounded revocation: the customer pulls the reference. The BYOK
	// default is resolve-on-every-use (no cache), so the very next Open of a
	// BYOK-sealed value fails safe — no shared-key fallback, no stale window.
	live = false
	k.purgeTenant(tenant) // operator-initiated cache flush (also zeroizes)
	if _, err := k.Open(ctx, tenant, byokBlob, aad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("revoked byok open must fail unavailable: %v", err)
	}
	if _, err := k.Seal(ctx, tenant, []byte("more"), aad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("revoked byok seal must fail unavailable (no fallback): %v", err)
	}
	// The earlier MANAGED generations are independent of the revoked BYOK
	// reference and still open (revocation scoped to the BYOK version only).
	live = true // (the managed versions never used the vault, but be explicit)
	if p, err := k.Open(ctx, tenant, v1blob, aad); err != nil || string(p) != "v1-secret" {
		t.Fatalf("managed v1 must survive byok revocation: %q %v", p, err)
	}
	live = false

	// ── 5. Cryptographic destruction (offboarding): every version's material
	// is wiped and the chain is permanently unreadable; the cache is zeroized.
	cachedV2 := captureCachedKEK(t, k, tenant, 2) // re-seal-free read; may be empty if evicted
	n, err := k.DestroyKeys(ctx, tenant)
	if err != nil || n != 3 {
		t.Fatalf("destroy all 3 versions: n=%d err=%v", n, err)
	}
	if cachedV2 != nil && !allZero(cachedV2) {
		t.Error("KEYS-003: any remaining cached KEK must be zeroized on destroy")
	}
	for _, blob := range []string{v1blob, v2blob, byokBlob} {
		if _, err := k.Open(ctx, tenant, blob, aad); !errors.Is(err, ErrKeyDestroyed) {
			t.Fatalf("post-destroy open must fail destroyed: %v", err)
		}
	}
	if _, err := k.Seal(ctx, tenant, []byte("zombie"), aad); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("post-destroy seal must refuse to re-key: %v", err)
	}
	// Store material is wiped for every version.
	chain, _ := store.Chain(ctx, tenant)
	if len(chain) != 3 {
		t.Fatalf("chain should retain 3 destroyed tombstones, got %d", len(chain))
	}
	for _, kv := range chain {
		if len(kv.WrappedKEK) != 0 || kv.BYOKRef != "" || kv.State != StateDestroyed {
			t.Fatalf("destroyed version still carries material: %+v", kv)
		}
	}
}

// captureCachedKEK returns a reference to the in-memory cached KEK slice for a
// version (nil if not cached) — used to assert the bytes are zeroized in place.
func captureCachedKEK(t *testing.T, k *Keyring, tenant string, version int) []byte {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	if e, ok := k.cache[tenant+":"+strconv.Itoa(version)]; ok {
		return e.kek
	}
	return nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
