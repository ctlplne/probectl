// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package tenantkeys

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

func testMaster(t *testing.T) *crypto.Envelope {
	t.Helper()
	kek := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	kp, err := crypto.NewStaticKeyProviderFromBase64("master", kek)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.NewEnvelope(kp)
}

func newRing(t *testing.T, resolve RefResolver) (*Keyring, *MemStore) {
	t.Helper()
	store := NewMemStore()
	k, err := NewKeyring(store, testMaster(t), resolve)
	if err != nil {
		t.Fatal(err)
	}
	return k, store
}

func byokMaterial(material string) ([]byte, func()) {
	b := []byte(material)
	return b, func() { crypto.Zeroize(b) }
}

type recordingProvider struct {
	base       crypto.Provider
	encryptKey []byte
	decryptKey []byte
}

func (p *recordingProvider) Hash(data []byte) []byte { return p.base.Hash(data) }

func (p *recordingProvider) Random(n int) ([]byte, error) { return p.base.Random(n) }

func (p *recordingProvider) Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	p.encryptKey = key
	return p.base.Encrypt(key, plaintext, aad)
}

func (p *recordingProvider) Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	p.decryptKey = key
	return p.base.Decrypt(key, ciphertext, aad)
}

func (p *recordingProvider) Sign(key, data []byte) []byte { return p.base.Sign(key, data) }

func (p *recordingProvider) Verify(key, data, mac []byte) bool {
	return p.base.Verify(key, data, mac)
}

// TestPerTenantIsolation is the named isolation test: tenant A's key cannot
// read tenant B's data — a blob sealed for A fails to open as B (and vice
// versa), even with identical plaintext/AAD.
func TestPerTenantIsolation(t *testing.T) {
	k, _ := newRing(t, nil)
	ctx := context.Background()
	aad := []byte("alert-channel-secret")

	sealedA, err := k.Seal(ctx, "tnA", []byte("hmac-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	sealedB, err := k.Seal(ctx, "tnB", []byte("hmac-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if sealedA == sealedB {
		t.Fatal("two tenants sealing the same plaintext must not produce the same blob")
	}

	// The right tenant opens its own.
	plain, err := k.Open(ctx, "tnA", sealedA, aad)
	if err != nil || string(plain) != "hmac-secret" {
		t.Fatalf("own open: %q %v", plain, err)
	}
	// The WRONG tenant cannot open it — cross-tenant replay fails.
	if _, err := k.Open(ctx, "tnB", sealedA, aad); err == nil {
		t.Fatal("tenant B must not open tenant A's blob")
	}
	if _, err := k.Open(ctx, "tnA", sealedB, aad); err == nil {
		t.Fatal("tenant A must not open tenant B's blob")
	}
}

// TestRotationNoDowntime is the named rotation test: after rotation, v1
// blobs still open (retired = decrypt-only), new seals carry v2, and both
// generations decrypt — no downtime, no re-encryption required.
func TestRotationNoDowntime(t *testing.T) {
	k, store := newRing(t, nil)
	ctx := context.Background()
	aad := []byte("x")

	v1blob, err := k.Seal(ctx, "tnA", []byte("first"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v1blob, "tk1:1:") {
		t.Fatalf("v1 format: %s", v1blob)
	}

	kv, err := k.Rotate(ctx, "tnA", ModeManaged, "")
	if err != nil || kv.Version != 2 {
		t.Fatalf("rotate: %+v %v", kv, err)
	}
	v2blob, err := k.Seal(ctx, "tnA", []byte("second"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v2blob, "tk1:2:") {
		t.Fatalf("new seals must use the new version: %s", v2blob)
	}
	// Both generations open.
	if p, err := k.Open(ctx, "tnA", v1blob, aad); err != nil || string(p) != "first" {
		t.Fatalf("v1 after rotation: %q %v", p, err)
	}
	if p, err := k.Open(ctx, "tnA", v2blob, aad); err != nil || string(p) != "second" {
		t.Fatalf("v2: %q %v", p, err)
	}
	// The chain shows v1 retired, v2 active.
	chain, _ := store.Chain(ctx, "tnA")
	if len(chain) != 2 || chain[0].State != StateActive || chain[1].State != StateRetired {
		t.Fatalf("chain: %+v", chain)
	}
}

// TestCryptoOffboard is the named offboarding test: destroying the tenant's
// keys renders every blob permanently unreadable, sealing refuses to
// silently re-key, key material is wiped from the store, and the other
// tenant is untouched.
func TestCryptoOffboard(t *testing.T) {
	k, store := newRing(t, nil)
	ctx := context.Background()
	aad := []byte("x")

	blobA, _ := k.Seal(ctx, "tnA", []byte("doomed"), aad)
	_, _ = k.Rotate(ctx, "tnA", ModeManaged, "")
	blobA2, _ := k.Seal(ctx, "tnA", []byte("doomed-v2"), aad)
	blobB, _ := k.Seal(ctx, "tnB", []byte("survivor"), aad)

	n, err := k.DestroyKeys(ctx, "tnA")
	if err != nil || n != 2 {
		t.Fatalf("destroy: n=%d err=%v", n, err)
	}
	// Every generation is unreadable, with the specific destroyed error.
	for _, blob := range []string{blobA, blobA2} {
		if _, err := k.Open(ctx, "tnA", blob, aad); !errors.Is(err, ErrKeyDestroyed) {
			t.Fatalf("post-destroy open must fail destroyed: %v", err)
		}
	}
	// Sealing after destruction refuses to re-key.
	if _, err := k.Seal(ctx, "tnA", []byte("new"), aad); !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("post-destroy seal must fail destroyed: %v", err)
	}
	// Key material is wiped from the store.
	chain, _ := store.Chain(ctx, "tnA")
	for _, kv := range chain {
		if len(kv.WrappedKEK) != 0 || kv.BYOKRef != "" || kv.State != StateDestroyed {
			t.Fatalf("material must be wiped: %+v", kv)
		}
	}
	// The other tenant is untouched.
	if p, err := k.Open(ctx, "tnB", blobB, aad); err != nil || string(p) != "survivor" {
		t.Fatalf("tenant B after A's offboarding: %q %v", p, err)
	}
}

// TestBYOKFailSafe: byok material resolves through the customer's reference;
// an unresolvable reference fails seal AND open with NO shared-key fallback;
// a dead reference is rejected BEFORE activation (the lockout guard).
func TestBYOKFailSafe(t *testing.T) {
	material := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	live := true
	resolve := func(_ context.Context, ref string) ([]byte, func(), error) {
		if !live {
			return nil, nil, errors.New("vault sealed")
		}
		if ref != "vault:kv/tenants/acme#kek" {
			return nil, nil, errors.New("not found")
		}
		b, cleanup := byokMaterial(material)
		return b, cleanup, nil
	}
	k, _ := newRing(t, resolve)
	ctx := context.Background()
	aad := []byte("x")

	// A dead reference cannot become the active key.
	if _, err := k.Rotate(ctx, "tnA", ModeBYOK, "vault:kv/wrong#ref"); err == nil {
		t.Fatal("a dead byok reference must be rejected before activation")
	}
	// A live one rotates in.
	kv, err := k.Rotate(ctx, "tnA", ModeBYOK, "vault:kv/tenants/acme#kek")
	if err != nil || kv.Mode != ModeBYOK {
		t.Fatalf("byok rotate: %+v %v", kv, err)
	}
	blob, err := k.Seal(ctx, "tnA", []byte("customer-keyed"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := k.Open(ctx, "tnA", blob, aad); err != nil || string(p) != "customer-keyed" {
		t.Fatalf("byok round-trip: %q %v", p, err)
	}

	// The customer revokes access: seal AND open fail safe — never a
	// fallback to the deployment master or any shared key.
	live = false
	k.purgeTenant("tnA")
	if _, err := k.Open(ctx, "tnA", blob, aad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("revoked byok open must fail unavailable: %v", err)
	}
	if _, err := k.Seal(ctx, "tnA", []byte("more"), aad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("revoked byok seal must fail unavailable: %v", err)
	}
}

// TestBYOKRevocationInstantTTLZero: KEYS-002. With the default BYOK TTL of 0
// (resolve-on-every-use), revoking the customer's reference makes Open fail
// within the SAME process WITHOUT any explicit cache purge — there is no 30s
// window during which a revoked BYOK key still decrypts.
func TestBYOKRevocationInstantTTLZero(t *testing.T) {
	material := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	live := true
	resolve := func(_ context.Context, _ string) ([]byte, func(), error) {
		if !live {
			return nil, nil, errors.New("revoked")
		}
		b, cleanup := byokMaterial(material)
		return b, cleanup, nil
	}
	k, _ := newRing(t, resolve)
	// Pin the clock so the test cannot accidentally rely on wall-clock TTL expiry.
	now := time.Unix(1_000, 0)
	k.WithClock(func() time.Time { return now })
	// Default byokTTL is 0; assert it (the property under test).
	if k.byokTTL != 0 {
		t.Fatalf("default byokTTL = %v, want 0 (resolve-on-every-use)", k.byokTTL)
	}
	ctx := context.Background()
	aad := []byte("x")

	kv, err := k.Rotate(ctx, "tnA", ModeBYOK, "vault:kv/acme#kek")
	if err != nil || kv.Mode != ModeBYOK {
		t.Fatalf("byok rotate: %+v %v", kv, err)
	}
	blob, err := k.Seal(ctx, "tnA", []byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := k.Open(ctx, "tnA", blob, aad); err != nil || string(p) != "secret" {
		t.Fatalf("pre-revocation open: %q %v", p, err)
	}

	// Revoke. NO purgeTenant, NO clock advance — TTL 0 means the next Open
	// re-resolves and finds the reference gone.
	live = false
	if _, err := k.Open(ctx, "tnA", blob, aad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("revoked byok open must fail unavailable immediately (TTL 0): %v", err)
	}
}

func TestBYOKPositiveTTLZeroizesExpiredCache(t *testing.T) {
	material := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	var resolves int
	resolve := func(_ context.Context, _ string) ([]byte, func(), error) {
		resolves++
		b, cleanup := byokMaterial(material)
		return b, cleanup, nil
	}
	k, _ := newRing(t, resolve)
	now := time.Unix(30_000, 0)
	k.WithClock(func() time.Time { return now }).WithBYOKTTL(time.Second)
	ctx := context.Background()
	aad := []byte("x")

	kv, err := k.Rotate(ctx, "tnA", ModeBYOK, "vault:kv/acme#kek")
	if err != nil || kv.Mode != ModeBYOK {
		t.Fatalf("byok rotate: %+v %v", kv, err)
	}
	blob, err := k.Seal(ctx, "tnA", []byte("secret"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	cached := captureCachedKEK(t, k, "tnA", kv.Version)
	if cached == nil || allZero(cached) {
		t.Fatalf("expected non-zero cached BYOK KEK before expiry: %x", cached)
	}
	resolvesBeforeCacheHit := resolves
	plain, err := k.Open(ctx, "tnA", blob, aad)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("open through live BYOK cache: %q %v", plain, err)
	}
	crypto.Zeroize(plain)
	if resolves != resolvesBeforeCacheHit {
		t.Fatalf("live BYOK cache hit re-resolved: before=%d after=%d", resolvesBeforeCacheHit, resolves)
	}

	now = now.Add(2 * time.Second)
	plain, err = k.Open(ctx, "tnA", blob, aad)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("open after BYOK cache expiry: %q %v", plain, err)
	}
	crypto.Zeroize(plain)
	if !allZero(cached) {
		t.Fatalf("expired BYOK cached KEK was not zeroized: %x", cached)
	}
	if resolves != resolvesBeforeCacheHit+1 {
		t.Fatalf("expected BYOK cache expiry to re-resolve once, before=%d after=%d", resolvesBeforeCacheHit, resolves)
	}
}

func TestBYOKResolverSlicesZeroizedAfterSealOpen(t *testing.T) {
	material := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	var resolved [][]byte
	resolve := func(_ context.Context, _ string) ([]byte, func(), error) {
		b, cleanup := byokMaterial(material)
		resolved = append(resolved, b)
		return b, cleanup, nil
	}
	k, _ := newRing(t, resolve)
	ctx := context.Background()
	aad := []byte("x")

	base := crypto.Default
	rec := &recordingProvider{base: base}
	crypto.Default = rec
	t.Cleanup(func() { crypto.Default = base })

	if _, err := k.Rotate(ctx, "tnA", ModeBYOK, "vault:kv/acme#kek"); err != nil {
		t.Fatalf("byok rotate: %v", err)
	}
	blob, err := k.Seal(ctx, "tnA", []byte("secret"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if rec.encryptKey == nil || !allZero(rec.encryptKey) {
		t.Fatalf("uncached BYOK seal KEK was not zeroized: %x", rec.encryptKey)
	}
	for i, b := range resolved {
		if !allZero(b) {
			t.Fatalf("resolved base64 material %d was not zeroized after seal path: %x", i, b)
		}
	}

	plain, err := k.Open(ctx, "tnA", blob, aad)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("open: %q %v", plain, err)
	}
	crypto.Zeroize(plain)
	if rec.decryptKey == nil || !allZero(rec.decryptKey) {
		t.Fatalf("uncached BYOK open KEK was not zeroized: %x", rec.decryptKey)
	}
	for i, b := range resolved {
		if !allZero(b) {
			t.Fatalf("resolved base64 material %d was not zeroized after open path: %x", i, b)
		}
	}
}

// TestManagedKEKCacheTTLZeroizesExpiredEntry is the KEYS-003 regression guard:
// an expired managed KEK cache hit must wipe the old cached bytes before the
// keyring unwraps and caches a fresh copy.
func TestManagedKEKCacheTTLZeroizesExpiredEntry(t *testing.T) {
	k, _ := newRing(t, nil)
	now := time.Unix(10_000, 0)
	k.WithClock(func() time.Time { return now }).WithTTL(time.Second)
	ctx := context.Background()
	aad := []byte("x")

	blob, err := k.Seal(ctx, "tnA", []byte("secret"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	expired := captureCachedKEK(t, k, "tnA", 1)
	if expired == nil || allZero(expired) {
		t.Fatalf("expected non-zero cached KEK before expiry: %x", expired)
	}

	now = now.Add(2 * time.Second)
	plain, err := k.Open(ctx, "tnA", blob, aad)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("open through refreshed cache: %q %v", plain, err)
	}
	if !allZero(expired) {
		t.Fatalf("expired cached KEK was not zeroized: %x", expired)
	}
	refreshed := captureCachedKEK(t, k, "tnA", 1)
	if refreshed == nil || allZero(refreshed) {
		t.Fatalf("expected refreshed non-zero cached KEK after open: %x", refreshed)
	}
}

// TestManagedKEKCacheOverwriteZeroizesPreviousEntry is the KEYS-003 overwrite
// guard: replacing a cache entry must wipe the old entry's raw bytes first.
func TestManagedKEKCacheOverwriteZeroizesPreviousEntry(t *testing.T) {
	k, _ := newRing(t, nil)
	k.WithTTL(time.Minute)

	first := bytes.Repeat([]byte{0x11}, 32)
	second := bytes.Repeat([]byte{0x22}, 32)
	k.cachePut("tnA", 1, ModeManaged, first)
	oldCached := captureCachedKEK(t, k, "tnA", 1)
	if oldCached == nil || allZero(oldCached) {
		t.Fatalf("expected non-zero first cached KEK: %x", oldCached)
	}

	k.cachePut("tnA", 1, ModeManaged, second)
	if !allZero(oldCached) {
		t.Fatalf("overwritten cached KEK was not zeroized: %x", oldCached)
	}
	current := captureCachedKEK(t, k, "tnA", 1)
	if !bytes.Equal(current, second) {
		t.Fatalf("current cached KEK = %x, want %x", current, second)
	}
}

func TestManagedCacheEvictionPreservesRotationReads(t *testing.T) {
	k, _ := newRing(t, nil)
	now := time.Unix(20_000, 0)
	k.WithClock(func() time.Time { return now }).WithTTL(time.Second)
	ctx := context.Background()
	aad := []byte("x")

	v1, err := k.Seal(ctx, "tnA", []byte("first"), aad)
	if err != nil {
		t.Fatalf("seal v1: %v", err)
	}
	cachedV1 := captureCachedKEK(t, k, "tnA", 1)
	if cachedV1 == nil || allZero(cachedV1) {
		t.Fatalf("expected cached v1 KEK before rotation: %x", cachedV1)
	}
	if _, err := k.Rotate(ctx, "tnA", ModeManaged, ""); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !allZero(cachedV1) {
		t.Fatalf("rotation did not zeroize evicted v1 cache entry: %x", cachedV1)
	}
	v2, err := k.Seal(ctx, "tnA", []byte("second"), aad)
	if err != nil {
		t.Fatalf("seal v2: %v", err)
	}
	cachedV2 := captureCachedKEK(t, k, "tnA", 2)
	if cachedV2 == nil || allZero(cachedV2) {
		t.Fatalf("expected cached v2 KEK before TTL eviction: %x", cachedV2)
	}

	now = now.Add(2 * time.Second)
	if p, err := k.Open(ctx, "tnA", v1, aad); err != nil || string(p) != "first" {
		t.Fatalf("v1 after rotation/cache eviction: %q %v", p, err)
	} else {
		crypto.Zeroize(p)
	}
	if p, err := k.Open(ctx, "tnA", v2, aad); err != nil || string(p) != "second" {
		t.Fatalf("v2 after rotation/cache eviction: %q %v", p, err)
	} else {
		crypto.Zeroize(p)
	}
	if !allZero(cachedV2) {
		t.Fatalf("TTL eviction did not zeroize old v2 cache entry: %x", cachedV2)
	}
}

// TestSeamIntegration: the keyring rides the core tenantcrypto seam — new
// seals are tenant-keyed, legacy deployment-sealed and plaintext values keep
// opening, and the seam's DestroyKeys reaches the keyring.
func TestSeamIntegration(t *testing.T) {
	defer tenantcrypto.Reset()
	tenantcrypto.Reset()

	// The pre-S-T6 deployment sealer minted a legacy value.
	dep, err := tenantcrypto.NewEnvelopeSealer("deployment", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(dep)
	ctx := context.Background()
	aad := []byte("alert-channel-secret")
	legacy, err := tenantcrypto.Seal(ctx, "tnA", []byte("old-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}

	// S-T6 installs the keyring as primary; the deployment sealer stays an
	// opener (decrypt-on-read compatibility).
	k, _ := newRing(t, nil)
	tenantcrypto.SetPrimary(k)
	tenantcrypto.AddOpener(dep)

	fresh, err := tenantcrypto.Seal(ctx, "tnA", []byte("new-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fresh, "tk1:") {
		t.Fatalf("new seals must be tenant-keyed: %s", fresh)
	}
	for stored, want := range map[string]string{
		fresh:        "new-secret",
		legacy:       "old-secret",
		"plain-text": "plain-text", // pre-envelope rows
	} {
		p, err := tenantcrypto.Open(ctx, "tnA", stored, aad)
		if err != nil || string(p) != want {
			t.Fatalf("open %q: %q %v", stored, p, err)
		}
	}

	// The seam reaches the keyring for crypto-offboarding.
	if n, supported, err := tenantcrypto.DestroyKeys(ctx, "tnA"); err != nil || !supported || n != 1 {
		t.Fatalf("seam destroy: n=%d supported=%v err=%v", n, supported, err)
	}
	if _, err := tenantcrypto.Open(ctx, "tnA", fresh, aad); err == nil {
		t.Fatal("post-destroy open through the seam must fail")
	}
	// Legacy deployment-sealed values are NOT tenant-keyed — they still open
	// (their store line in the erase attestation is the deletion path).
	if _, err := tenantcrypto.Open(ctx, "tnA", legacy, aad); err != nil {
		t.Fatalf("legacy value after key destroy: %v", err)
	}
}

// TestFailSafeOnStoreOutage: a key-store outage is an ERROR on seal and
// open — never a silent fallback.
func TestFailSafeOnStoreOutage(t *testing.T) {
	k, store := newRing(t, nil)
	ctx := context.Background()
	blob, _ := k.Seal(ctx, "tnA", []byte("x"), nil)
	store.FailAll(true)
	k.purgeTenant("tnA")
	if _, err := k.Seal(ctx, "tnA", []byte("y"), nil); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("seal during outage: %v", err)
	}
	if _, err := k.Open(ctx, "tnA", blob, nil); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("open during outage: %v", err)
	}
}

// TestManagerAdapter: the core KeyManager contract over the keyring — chain
// state crosses as DTOs (never material), rotation maps modes/refs through.
func TestManagerAdapter(t *testing.T) {
	k, _ := newRing(t, nil)
	m := NewManager(k)
	ctx := context.Background()

	if _, err := k.Seal(ctx, "tnA", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	info, err := m.RotateKey(ctx, "tnA", ModeManaged, "")
	if err != nil || info.Version != 2 || info.Mode != ModeManaged || info.State != StateActive {
		t.Fatalf("rotate via manager: %+v %v", info, err)
	}
	chain, err := m.KeyStatus(ctx, "tnA")
	if err != nil || len(chain) != 2 {
		t.Fatalf("status: %+v %v", chain, err)
	}
	if chain[0].Version != 2 || chain[0].State != StateActive {
		t.Fatalf("newest first: %+v", chain[0])
	}
	if chain[1].State != StateRetired || chain[1].RetiredAt == "" {
		t.Fatalf("retired with timestamp: %+v", chain[1])
	}
	if chain[0].CreatedAt == "" {
		t.Fatal("created_at must serialize")
	}
	// Invalid mode is rejected before touching the chain.
	if _, err := m.RotateKey(ctx, "tnA", "weird", ""); err == nil {
		t.Fatal("invalid mode must be rejected")
	}
	// byok without a ref is rejected.
	if _, err := m.RotateKey(ctx, "tnA", ModeBYOK, ""); err == nil {
		t.Fatal("byok without ref must be rejected")
	}
}

// TestStatusNeverLeaksMaterial: the Status path strips wrapped KEKs and
// refs stay (operators need the pointer) but raw key bytes never surface.
func TestStatusNeverLeaksMaterial(t *testing.T) {
	k, store := newRing(t, nil)
	ctx := context.Background()
	if _, err := k.Seal(ctx, "tnA", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	chain, err := k.Status(ctx, "tnA")
	if err != nil || len(chain) != 1 {
		t.Fatalf("status: %v %v", chain, err)
	}
	if len(chain[0].WrappedKEK) != 0 {
		t.Fatal("Status must not carry key material")
	}
	// The store itself still holds the wrapped KEK (Status strips, not wipes).
	raw, _ := store.Chain(ctx, "tnA")
	if len(raw[0].WrappedKEK) == 0 {
		t.Fatal("the store must retain the wrapped KEK")
	}
}
