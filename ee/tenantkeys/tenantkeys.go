// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
// See ee/doc.go for the boundary rules every ee/ file observes.

// Package tenantkeys is per-tenant key isolation / BYOK (S-T6, F56),
// unlocked by the byok license feature: each tenant's sensitive at-rest data
// is encrypted under ITS OWN key chain, rotation is downtime-free, and
// destroying a tenant's keys is a cryptographic offboarding event — every
// remaining ciphertext (including backups within their TTL) becomes
// permanently unreadable. The cryptographic complement to S-T2's physical
// isolation.
//
// Key modes:
//   - managed (default): probectl generates the tenant KEK and stores it
//     WRAPPED under the deployment master (PROBECTL_ENVELOPE_KEY) — never
//     plaintext at rest.
//   - byok: the tenant KEK lives in the CUSTOMER's secret system; probectl
//     stores only the S41 secret REFERENCE (vault:/aws:/azure:/gcp:/
//     cyberark:) and resolves the key material at use time. The customer can
//     revoke probectl's access — or destroy the key — at any moment, which
//     is the point AND the lockout risk (docs/byok.md states the model).
//
// The fail-safe rule (the S-T6 watch-out): an unavailable, unresolvable, or
// destroyed key is an ERROR. There is no fallback to the deployment master
// or any shared key for tenant-keyed data, ever.
package tenantkeys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// Scheme is the stored-format prefix for tenant-keyed values.
const Scheme = "tk1"

// Key modes and states (mirror migration 0030).
const (
	ModeManaged = "managed"
	ModeBYOK    = "byok"

	StateActive    = "active"
	StateRetired   = "retired"
	StateDestroyed = "destroyed"
)

// Errors the keyring fails SAFE with.
var (
	ErrKeyDestroyed   = errors.New("tenantkeys: the tenant's keys are destroyed (cryptographic offboarding) — ciphertexts are permanently unreadable")
	ErrKeyUnavailable = errors.New("tenantkeys: tenant key unavailable — failing safe (no shared-key fallback)")
	ErrNoActiveKey    = errors.New("tenantkeys: tenant has no active key")
)

// KeyVersion is one link of a tenant's key chain.
type KeyVersion struct {
	TenantID    string     `json:"tenant_id"`
	Version     int        `json:"version"`
	Mode        string     `json:"mode"`
	State       string     `json:"state"`
	WrappedKEK  []byte     `json:"-"` // managed only; sealed under the master
	BYOKRef     string     `json:"byok_ref,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
	DestroyedAt *time.Time `json:"destroyed_at,omitempty"`
}

// Store persists key chains.
type Store interface {
	// ActiveVersion returns the tenant's active key (nil = none yet).
	ActiveVersion(ctx context.Context, tenantID string) (*KeyVersion, error)
	// Version returns one specific version (nil = absent).
	Version(ctx context.Context, tenantID string, version int) (*KeyVersion, error)
	// Insert adds a new version (the caller assigns version numbers).
	Insert(ctx context.Context, kv KeyVersion) error
	// Retire marks the tenant's active version retired (before activating a
	// successor).
	Retire(ctx context.Context, tenantID string, at time.Time) error
	// DestroyAll wipes key material for EVERY version (wrapped KEKs nulled,
	// byok refs cleared, state destroyed) and returns how many versions.
	DestroyAll(ctx context.Context, tenantID, by string, at time.Time) (int, error)
	// Chain lists every version, newest first (status surfaces).
	Chain(ctx context.Context, tenantID string) ([]KeyVersion, error)
}

// RefResolver resolves a BYOK secret reference to base64 key material (the
// S41 resolver in production).
type RefResolver func(ctx context.Context, ref string) (string, error)

// Keyring implements tenantcrypto.Sealer + Destroyer over a Store: the
// per-tenant envelope. KEKs cache briefly; every cache entry is keyed
// (tenant, version) — one tenant's key can never answer for another's.
type Keyring struct {
	store   Store
	master  *crypto.Envelope // wraps managed KEKs at rest
	resolve RefResolver      // BYOK material at use time
	now     func() time.Time
	ttl     time.Duration

	byokTTL time.Duration // KEYS-002: BYOK cache TTL (default 0 = resolve-on-every-use)

	mu    sync.Mutex
	cache map[string]cachedKEK
}

type cachedKEK struct {
	kek     []byte
	fetched time.Time
}

// NewKeyring wires the keyring. master is REQUIRED (managed KEKs are sealed
// under it); resolve is required only for byok tenants (nil = byok refused).
func NewKeyring(store Store, master *crypto.Envelope, resolve RefResolver) (*Keyring, error) {
	if store == nil || master == nil {
		return nil, errors.New("tenantkeys: store and the deployment master envelope are required")
	}
	return &Keyring{store: store, master: master, resolve: resolve,
		now: time.Now, ttl: 30 * time.Second, byokTTL: 0, cache: map[string]cachedKEK{}}, nil
}

// WithClock overrides time (tests).
func (k *Keyring) WithClock(now func() time.Time) *Keyring {
	k.now = now
	return k
}

// WithTTL overrides the managed-KEK cache TTL (KEYS-003). A non-positive value
// means resolve-on-every-use (no caching) for managed keys.
func (k *Keyring) WithTTL(ttl time.Duration) *Keyring {
	k.ttl = ttl
	return k
}

// WithBYOKTTL overrides the BYOK cache TTL (KEYS-002). It DEFAULTS to 0
// (resolve-on-every-use) so a revoked/purged BYOK reference stops decrypting
// within the same process immediately — BYOK revocation is effectively
// instantaneous, not bounded by a 30s window.
func (k *Keyring) WithBYOKTTL(ttl time.Duration) *Keyring {
	k.byokTTL = ttl
	return k
}

// ttlFor returns the cache TTL for a key version's mode (KEYS-002).
func (k *Keyring) ttlFor(mode string) time.Duration {
	if mode == ModeBYOK {
		return k.byokTTL
	}
	return k.ttl
}

// zeroize best-effort wipes a key's bytes (KEYS-003) via the crypto provider
// helper, so key-handling stays inside internal/crypto's surface.
func zeroize(b []byte) { crypto.Zeroize(b) }

// Scheme implements tenantcrypto.Sealer.
func (*Keyring) Scheme() string { return Scheme }

// ensureActive returns the tenant's active version, provisioning a managed
// v1 on first use (every tenant gets its own key the first time anything is
// sealed — no opt-in gap).
func (k *Keyring) ensureActive(ctx context.Context, tenantID string) (*KeyVersion, error) {
	kv, err := k.store.ActiveVersion(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	if kv != nil {
		return kv, nil
	}
	// Destroyed chains must NOT silently re-key: sealing after offboarding
	// is a logic error, not a fresh start.
	chain, err := k.store.Chain(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	for _, v := range chain {
		if v.State == StateDestroyed {
			return nil, ErrKeyDestroyed
		}
	}
	kv2, err := k.provisionManaged(ctx, tenantID, 1)
	if err != nil {
		return nil, err
	}
	return kv2, nil
}

// provisionManaged mints a managed KEK as the given version.
func (k *Keyring) provisionManaged(ctx context.Context, tenantID string, version int) (*KeyVersion, error) {
	kek, err := crypto.Random(32)
	if err != nil {
		return nil, err
	}
	sealed, err := k.master.Seal(ctx, kek, []byte("tenant-kek:"+tenantID+":"+strconv.Itoa(version)))
	if err != nil {
		return nil, err
	}
	kv := KeyVersion{
		TenantID: tenantID, Version: version, Mode: ModeManaged, State: StateActive,
		WrappedKEK: encodeSealed(sealed), CreatedAt: k.now().UTC(),
	}
	if err := k.store.Insert(ctx, kv); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	k.cachePut(tenantID, version, ModeManaged, kek)
	return &kv, nil
}

// kekFor returns the raw KEK for (tenant, version), failing safe.
func (k *Keyring) kekFor(ctx context.Context, kv *KeyVersion) ([]byte, error) {
	if kv.State == StateDestroyed {
		return nil, ErrKeyDestroyed
	}
	ttl := k.ttlFor(kv.Mode)
	key := kv.TenantID + ":" + strconv.Itoa(kv.Version)
	if ttl > 0 {
		if kek, ok := k.cacheGet(key, ttl); ok {
			return kek, nil
		}
	}

	var kek []byte
	switch kv.Mode {
	case ModeManaged:
		sealed, err := decodeSealed(kv.WrappedKEK)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
		}
		kek, err = k.master.Open(ctx, sealed, []byte("tenant-kek:"+kv.TenantID+":"+strconv.Itoa(kv.Version)))
		if err != nil {
			return nil, fmt.Errorf("%w: unwrap managed kek: %v", ErrKeyUnavailable, err)
		}
	case ModeBYOK:
		if k.resolve == nil {
			return nil, fmt.Errorf("%w: no secret-reference resolver configured for byok", ErrKeyUnavailable)
		}
		material, err := k.resolve(ctx, kv.BYOKRef)
		if err != nil {
			return nil, fmt.Errorf("%w: byok reference: %v", ErrKeyUnavailable, err)
		}
		kek, err = base64.StdEncoding.DecodeString(strings.TrimSpace(material))
		if err != nil || len(kek) != 32 {
			return nil, fmt.Errorf("%w: byok material must be base64 of exactly 32 bytes", ErrKeyUnavailable)
		}
	default:
		return nil, fmt.Errorf("%w: unknown key mode %q", ErrKeyUnavailable, kv.Mode)
	}
	k.cachePut(kv.TenantID, kv.Version, kv.Mode, kek)
	return kek, nil
}

// cacheGet returns a cached KEK when still inside TTL. If the entry exists but
// has expired, the cached raw bytes are zeroized and the entry is removed before
// the caller unwraps/resolves a fresh copy (KEYS-003).
func (k *Keyring) cacheGet(key string, ttl time.Duration) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.cache[key]
	if !ok {
		return nil, false
	}
	if k.now().Sub(e.fetched) < ttl {
		return e.kek, true
	}
	zeroize(e.kek)
	delete(k.cache, key)
	return nil, false
}

// cachePut stores a KEK only when caching is enabled for its mode (KEYS-003).
// With TTL 0 (the BYOK default) nothing is retained, so a revoked reference
// cannot be served from a stale cache entry.
func (k *Keyring) cachePut(tenantID string, version int, mode string, kek []byte) {
	if k.ttlFor(mode) <= 0 {
		return
	}
	k.mu.Lock()
	key := tenantID + ":" + strconv.Itoa(version)
	if old, ok := k.cache[key]; ok {
		zeroize(old.kek)
	}
	k.cache[key] = cachedKEK{kek: kek, fetched: k.now()}
	k.mu.Unlock()
}

// purgeTenant drops every cached KEK of a tenant (rotation/destroy), zeroizing
// the bytes on the way out (KEYS-003, best-effort).
func (k *Keyring) purgeTenant(tenantID string) {
	k.mu.Lock()
	for key, e := range k.cache {
		if strings.HasPrefix(key, tenantID+":") {
			zeroize(e.kek)
			delete(k.cache, key)
		}
	}
	k.mu.Unlock()
}

// Seal encrypts plaintext under the tenant's ACTIVE key version. Format:
// tk1:<version>:<b64 ciphertext> (the tenant is bound via AAD, not trusted
// from the stored value).
func (k *Keyring) Seal(ctx context.Context, tenantID string, plaintext, aad []byte) (string, error) {
	kv, err := k.ensureActive(ctx, tenantID)
	if err != nil {
		return "", err
	}
	kek, err := k.kekFor(ctx, kv)
	if err != nil {
		return "", err
	}
	ct, err := crypto.Encrypt(kek, plaintext, sealAAD(tenantID, kv.Version, aad))
	if err != nil {
		return "", err
	}
	return Scheme + ":" + strconv.Itoa(kv.Version) + ":" + base64.RawStdEncoding.EncodeToString(ct), nil
}

// Open decrypts a tk1 value with the version that sealed it (active OR
// retired — rotation never breaks reads; destroyed fails safe).
func (k *Keyring) Open(ctx context.Context, tenantID string, stored string, aad []byte) ([]byte, error) {
	parts := strings.Split(stored, ":")
	if len(parts) != 3 || parts[0] != Scheme {
		return nil, errors.New("tenantkeys: malformed tk1 value")
	}
	version, err := strconv.Atoi(parts[1])
	if err != nil || version < 1 {
		return nil, errors.New("tenantkeys: malformed tk1 version")
	}
	kv, err := k.store.Version(ctx, tenantID, version)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	if kv == nil {
		// The version does not exist FOR THIS TENANT — a cross-tenant replay
		// or a destroyed-and-erased chain. Either way: fail safe.
		return nil, ErrKeyUnavailable
	}
	kek, err := k.kekFor(ctx, kv)
	if err != nil {
		return nil, err
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("tenantkeys: malformed tk1 ciphertext")
	}
	plain, err := crypto.Decrypt(kek, ct, sealAAD(tenantID, version, aad))
	if err != nil {
		return nil, fmt.Errorf("tenantkeys: decrypt failed (wrong tenant key or tampered value): %w", err)
	}
	return plain, nil
}

// Rotate activates a new key version for NEW seals; the outgoing version is
// retired (decrypt-only) — no downtime, no re-encryption required. mode
// "managed" mints a fresh KEK; "byok" binds the given secret reference
// (validated resolvable FIRST — a dead reference must not become the active
// key and lock the tenant out on the next write).
func (k *Keyring) Rotate(ctx context.Context, tenantID, mode, byokRef string) (*KeyVersion, error) {
	if mode != ModeManaged && mode != ModeBYOK {
		return nil, fmt.Errorf("tenantkeys: mode must be %q or %q", ModeManaged, ModeBYOK)
	}
	chain, err := k.store.Chain(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	next := 1
	for _, v := range chain {
		if v.State == StateDestroyed {
			return nil, ErrKeyDestroyed
		}
		if v.Version >= next {
			next = v.Version + 1
		}
	}
	if mode == ModeBYOK {
		if k.resolve == nil {
			return nil, fmt.Errorf("%w: no secret-reference resolver configured for byok", ErrKeyUnavailable)
		}
		probe := KeyVersion{TenantID: tenantID, Version: next, Mode: ModeBYOK, BYOKRef: byokRef, State: StateActive}
		if _, err := k.kekFor(ctx, &probe); err != nil {
			return nil, fmt.Errorf("tenantkeys: byok reference rejected before activation (lockout guard): %w", err)
		}
	}
	if err := k.store.Retire(ctx, tenantID, k.now().UTC()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	var kv *KeyVersion
	if mode == ModeManaged {
		kv, err = k.provisionManaged(ctx, tenantID, next)
		if err != nil {
			return nil, err
		}
	} else {
		v := KeyVersion{TenantID: tenantID, Version: next, Mode: ModeBYOK, State: StateActive,
			BYOKRef: byokRef, CreatedAt: k.now().UTC()}
		if err := k.store.Insert(ctx, v); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
		}
		kv = &v
	}
	k.purgeTenant(tenantID)
	return kv, nil
}

// DestroyKeys implements tenantcrypto.Destroyer: cryptographic offboarding.
// Every version's key material is wiped (wrapped KEKs nulled, byok refs
// cleared) and the chain is marked destroyed — Open and Seal fail safe from
// the next call on.
func (k *Keyring) DestroyKeys(ctx context.Context, tenantID string) (int, error) {
	n, err := k.store.DestroyAll(ctx, tenantID, "erase", k.now().UTC())
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}
	k.purgeTenant(tenantID)
	return n, nil
}

// Status returns the tenant's chain for the security-settings surface
// (key MATERIAL never leaves the keyring).
func (k *Keyring) Status(ctx context.Context, tenantID string) ([]KeyVersion, error) {
	chain, err := k.store.Chain(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	// Strip key material: Status feeds surfaces (API/console) — only chain
	// STATE crosses. The byok ref stays (it is a pointer, not a key).
	for i := range chain {
		chain[i].WrappedKEK = nil
	}
	return chain, nil
}

func sealAAD(tenantID string, version int, aad []byte) []byte {
	return append(tenantcrypto.BindAAD(tenantID, aad), []byte(":v"+strconv.Itoa(version))...)
}

// encodeSealed/decodeSealed flatten a crypto.Sealed for the wrapped_kek
// column (keyid|wrapped|ct, length-prefixed via base64+colons).
func encodeSealed(s crypto.Sealed) []byte {
	return []byte(s.KeyID + ":" +
		base64.RawStdEncoding.EncodeToString(s.WrappedDEK) + ":" +
		base64.RawStdEncoding.EncodeToString(s.Ciphertext))
}

func decodeSealed(b []byte) (crypto.Sealed, error) {
	parts := strings.Split(string(b), ":")
	if len(parts) != 3 {
		return crypto.Sealed{}, errors.New("tenantkeys: malformed wrapped kek")
	}
	wrapped, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return crypto.Sealed{}, err
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return crypto.Sealed{}, err
	}
	return crypto.Sealed{KeyID: parts[0], WrappedDEK: wrapped, Ciphertext: ct}, nil
}
