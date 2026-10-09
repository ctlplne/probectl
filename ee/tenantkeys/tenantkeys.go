// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

// Package tenantkeys is per-tenant key isolation / BYOK (S-T6, F56),
// unlocked by the byok license feature: each tenant's sensitive at-rest data
// is encrypted under ITS OWN key chain, rotation is downtime-free, and
// destroying a tenant's keys is a cryptographic offboarding event. How far that
// reaches into backups depends on the mode: under BYOK (probectl never holds
// the key) a pre-offboard backup becomes permanently unreadable once the
// customer destroys the key — true crypto-shred; under managed mode the tenant
// KEK is wrapped by the deployment master, which survives offboarding, so
// destruction crypto-shreds the live stores but a pre-offboard backup restored
// beside the live master still decrypts (managed offboarding relies on
// verifiable deletion + backup TTL, not backup crypto-shred — see
// docs/byok.md). The cryptographic complement to S-T2's physical isolation.
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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/secrets"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
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

	ErrRotationCommit = errors.New("tenantkeys: atomic key rotation transaction failed")
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

// RotationBuilder builds the next active key after RotateAtomic has serialized
// the tenant's chain and selected the next version. Implementations must not
// publish the returned key unless predecessor retirement, successor insertion,
// and the mandatory audit append can all commit.
type RotationBuilder func(ctx context.Context, nextVersion int) (KeyVersion, error)

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
	// RotateAtomic serializes one tenant's chain and commits predecessor
	// retirement, successor insertion, and the mandatory audit event as one
	// unit. Any failure leaves the previous active version unchanged.
	RotateAtomic(ctx context.Context, tenantID, actor string, at time.Time, build RotationBuilder) (*KeyVersion, error)
	// AllManaged lists every managed, non-destroyed version that still holds a
	// wrapped KEK, across ALL tenants (provider scope). It is the inventory the
	// deployment-envelope rewrap walks (CRY-02).
	AllManaged(ctx context.Context) ([]KeyVersion, error)
	// UpdateWrappedKEK replaces one managed version's sealed KEK in place — the
	// re-seal step of an envelope rewrap. It never touches BYOK rows.
	UpdateWrappedKEK(ctx context.Context, tenantID string, version int, wrapped []byte) error
}

// RefResolver resolves a BYOK secret reference to base64-encoded key material
// bytes (the S41 resolver in production). The cleanup function must wipe the
// returned bytes when the keyring is done decoding them.
type RefResolver func(ctx context.Context, ref string) ([]byte, func(), error)

// TenantToken, when it appears in a BYOK reference prefix, is replaced with the
// tenant id at check time so each tenant is pinned to its OWN reference
// namespace — a tenant admin cannot name another tenant's (or the deployment's)
// secret. docs/configuration.md documents the operator knob.
const TenantToken = "{tenant}"

// BYOKRefPolicy restricts which secret references a TENANT may bind as its BYOK
// key source. A BYOK reference submitted through the per-tenant keys API is
// UNTRUSTED tenant input that the keyring resolves with the DEPLOYMENT's own
// secret-store credentials; without this fence a tenant admin could point the
// control plane's resolver at any secret it can read (confused deputy / SSRF
// into the deployment secret store) or store literal key material verbatim in
// the DB (docs/guardrails.md G7-1, G7-6). The policy pins an operator-configured
// scheme+prefix; an empty prefix refuses BYOK references entirely (fail closed).
type BYOKRefPolicy struct {
	prefix string
}

// NewBYOKRefPolicy builds the policy from the operator-configured allowed
// reference prefix (PROBECTL_BYOK_REF_PREFIX), e.g.
// "vault:secret/data/probectl/byok/{tenant}/". An optional {tenant} token is
// substituted with the tenant id so references are per-tenant namespaced. An
// empty prefix means BYOK references are refused (fail closed) until an operator
// configures the namespace.
func NewBYOKRefPolicy(prefix string) BYOKRefPolicy {
	return BYOKRefPolicy{prefix: strings.TrimSpace(prefix)}
}

func (p BYOKRefPolicy) allowedPrefixFor(tenantID string) string {
	return strings.ReplaceAll(p.prefix, TenantToken, tenantID)
}

// reject returns a non-empty SERVER-SIDE reason category when ref is not an
// allowed BYOK reference for tenantID, or "" when it passes. It is pure (no
// I/O), the unit-testable core of the tenant-input gate. The reason strings are
// fixed categories (never tenant input) safe to log; callers must surface only
// the generic tenantcrypto.ErrBYOKRefRejected to the client.
func (p BYOKRefPolicy) reject(tenantID, ref string) string {
	r := strings.TrimSpace(ref)
	if p.prefix == "" {
		return "no byok reference namespace is configured for this deployment (PROBECTL_BYOK_REF_PREFIX)"
	}
	// env: would read the control plane's OWN process environment; a literal
	// (or the literal: escape) would store key MATERIAL verbatim in the DB.
	// Both are refused explicitly before the prefix check for a clear reason.
	if strings.HasPrefix(r, "env:") {
		return "env scheme is not tenant-bindable (reads the control plane's process environment)"
	}
	if !secrets.IsRef(r) {
		return "value is a literal, not a secret reference"
	}
	if want := p.allowedPrefixFor(tenantID); !strings.HasPrefix(r, want) {
		return "reference is outside the tenant's configured namespace"
	}
	// The prefix is a string fence, and a dot segment walks back out of it
	// wherever the path is cleaned before the lookup: Vault's listener answers
	// .../byok/<A>/../<B>/kek with a same-origin 301 to .../byok/<B>/kek, which
	// the resolver follows for a named host, and a normalizing front serves it
	// outright. A tenant's reference path must already be clean.
	refPath, _, _ := strings.Cut(r, "#")
	for _, seg := range strings.Split(refPath, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "reference path has an empty or dot segment"
		}
	}
	return ""
}

// Keyring implements tenantcrypto.Sealer + Destroyer over a Store: the
// per-tenant envelope. KEKs cache briefly; every cache entry is keyed
// (tenant, version) — one tenant's key can never answer for another's.
type Keyring struct {
	store     Store
	master    *crypto.Envelope // wraps managed KEKs at rest
	resolve   RefResolver      // BYOK material at use time
	refPolicy BYOKRefPolicy    // AUTHZ-10: fence on tenant-supplied BYOK refs (fail closed)
	log       *slog.Logger     // server-side rejection detail (never the ref value)
	now       func() time.Time
	ttl       time.Duration

	byokTTL time.Duration // KEYS-002: BYOK cache TTL (default 0 = resolve-on-every-use)

	mu    sync.Mutex
	cache map[string]cachedKEK
}

type cachedKEK struct {
	kek     []byte
	fetched time.Time
}

type keyLease struct {
	kek     []byte
	cleanup func()
}

func (l keyLease) Close() {
	if l.cleanup != nil {
		l.cleanup()
	}
}

func borrowedKEK(kek []byte) keyLease {
	return keyLease{kek: kek, cleanup: func() {}}
}

func ownedKEK(kek []byte) keyLease {
	return keyLease{kek: kek, cleanup: func() { zeroize(kek) }}
}

// NewKeyring wires the keyring. master is REQUIRED (managed KEKs are sealed
// under it); resolve is required only for byok tenants (nil = byok refused).
func NewKeyring(store Store, master *crypto.Envelope, resolve RefResolver) (*Keyring, error) {
	if store == nil || master == nil {
		return nil, errors.New("tenantkeys: store and the deployment master envelope are required")
	}
	return &Keyring{store: store, master: master, resolve: resolve,
		refPolicy: BYOKRefPolicy{}, log: slog.Default(),
		now: time.Now, ttl: 30 * time.Second, byokTTL: 0, cache: map[string]cachedKEK{}}, nil
}

// NewDeploymentKeyring is the keyring the control plane installs when byok is
// licensed (the ee attach seam): managed KEKs wrapped under the deployment
// master; BYOK keys resolved through the deployment's secret backends on every
// use, past the resolver's lease cache, so a customer's revocation applies on
// the next seal or open (KEYS-002, docs/byok.md); tenant references fenced to
// the operator's per-tenant namespace (AUTHZ-10).
func NewDeploymentKeyring(store Store, master *crypto.Envelope, resolver *secrets.Resolver, refPrefix string, log *slog.Logger) (*Keyring, error) {
	var resolve RefResolver
	if resolver != nil {
		resolve = resolver.ResolveBytesUncached
	}
	ring, err := NewKeyring(store, master, resolve)
	if err != nil {
		return nil, err
	}
	return ring.WithBYOKRefPolicy(NewBYOKRefPolicy(refPrefix)).WithLogger(log), nil
}

// WithBYOKRefPolicy pins the deployment's allowed tenant BYOK reference
// namespace (AUTHZ-10). The attach seam wires it from PROBECTL_BYOK_REF_PREFIX;
// the zero value refuses every BYOK reference (fail closed).
func (k *Keyring) WithBYOKRefPolicy(p BYOKRefPolicy) *Keyring {
	k.refPolicy = p
	return k
}

// WithLogger sets the logger used for the server-side detail of a rejected BYOK
// reference (the generic error alone crosses the API). nil keeps the default.
func (k *Keyring) WithLogger(l *slog.Logger) *Keyring {
	if l != nil {
		k.log = l
	}
	return k
}

// withClock overrides time (tests).
func (k *Keyring) withClock(now func() time.Time) *Keyring {
	k.now = now
	return k
}

// withTTL overrides the managed-KEK cache TTL (KEYS-003). A non-positive value
// means resolve-on-every-use (no caching) for managed keys.
func (k *Keyring) withTTL(ttl time.Duration) *Keyring {
	k.ttl = ttl
	return k
}

// withBYOKTTL overrides the BYOK cache TTL (KEYS-002). It DEFAULTS to 0
// (resolve-on-every-use) so a revoked/purged BYOK reference stops decrypting
// within the same process immediately — BYOK revocation is effectively
// instantaneous, not bounded by a 30s window.
func (k *Keyring) withBYOKTTL(ttl time.Duration) *Keyring {
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
	cached := false
	defer func() {
		if !cached {
			zeroize(kek)
		}
	}()
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
	cached = k.cachePut(tenantID, version, ModeManaged, kek)
	return &kv, nil
}

// kekFor returns the raw KEK for (tenant, version), failing safe.
func (k *Keyring) kekFor(ctx context.Context, kv *KeyVersion) (keyLease, error) {
	if kv.State == StateDestroyed {
		return keyLease{}, ErrKeyDestroyed
	}
	ttl := k.ttlFor(kv.Mode)
	key := kv.TenantID + ":" + strconv.Itoa(kv.Version)
	if ttl > 0 {
		if kek, ok := k.cacheGet(key, ttl); ok {
			return borrowedKEK(kek), nil
		}
	}

	var kek []byte
	switch kv.Mode {
	case ModeManaged:
		sealed, err := decodeSealed(kv.WrappedKEK)
		if err != nil {
			return keyLease{}, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
		}
		kek, err = k.master.Open(ctx, sealed, []byte("tenant-kek:"+kv.TenantID+":"+strconv.Itoa(kv.Version)))
		if err != nil {
			return keyLease{}, fmt.Errorf("%w: unwrap managed kek: %v", ErrKeyUnavailable, err)
		}
	case ModeBYOK:
		if k.resolve == nil {
			return keyLease{}, fmt.Errorf("%w: no secret-reference resolver configured for byok", ErrKeyUnavailable)
		}
		material, cleanup, err := k.resolve(ctx, kv.BYOKRef)
		if err != nil {
			return keyLease{}, fmt.Errorf("%w: byok reference: %v", ErrKeyUnavailable, err)
		}
		if cleanup != nil {
			defer cleanup()
		}
		trimmed := bytes.TrimSpace(material)
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
		n, err := base64.StdEncoding.Decode(decoded, trimmed)
		kek = decoded[:n]
		if err != nil || len(kek) != 32 {
			zeroize(decoded)
			return keyLease{}, fmt.Errorf("%w: byok material must be base64 of exactly 32 bytes", ErrKeyUnavailable)
		}
	default:
		return keyLease{}, fmt.Errorf("%w: unknown key mode %q", ErrKeyUnavailable, kv.Mode)
	}
	if k.cachePut(kv.TenantID, kv.Version, kv.Mode, kek) {
		return borrowedKEK(kek), nil
	}
	return ownedKEK(kek), nil
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
func (k *Keyring) cachePut(tenantID string, version int, mode string, kek []byte) bool {
	if k.ttlFor(mode) <= 0 {
		return false
	}
	k.mu.Lock()
	key := tenantID + ":" + strconv.Itoa(version)
	if old, ok := k.cache[key]; ok {
		zeroize(old.kek)
	}
	k.cache[key] = cachedKEK{kek: kek, fetched: k.now()}
	k.mu.Unlock()
	return true
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
	lease, err := k.kekFor(ctx, kv)
	if err != nil {
		return "", err
	}
	defer lease.Close()
	ct, err := crypto.Encrypt(lease.kek, plaintext, sealAAD(tenantID, kv.Version, aad))
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
	lease, err := k.kekFor(ctx, kv)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	ct, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("tenantkeys: malformed tk1 ciphertext")
	}
	plain, err := crypto.Decrypt(lease.kek, ct, sealAAD(tenantID, version, aad))
	if err != nil {
		return nil, fmt.Errorf("tenantkeys: decrypt failed (wrong tenant key or tampered value): %w", err)
	}
	return plain, nil
}

// rotate activates a new key version as the system actor. Interactive callers
// use RotateAudited so the authenticated actor is preserved in the mandatory
// audit event.
func (k *Keyring) rotate(ctx context.Context, tenantID, mode, byokRef string) (*KeyVersion, error) {
	return k.RotateAudited(ctx, tenantID, "system", mode, byokRef)
}

// RotateAudited activates a new key version for NEW seals; the outgoing
// version is retired (decrypt-only) — no downtime, no re-encryption required.
// Predecessor retirement, successor insertion, and the audit append are one
// store transaction. Mode "managed" mints a fresh KEK; "byok" binds the given
// secret reference, validated before the transaction so a dead reference can
// never become active and lock the tenant out.
func (k *Keyring) RotateAudited(ctx context.Context, tenantID, actor, mode, byokRef string) (*KeyVersion, error) {
	if mode != ModeManaged && mode != ModeBYOK {
		return nil, fmt.Errorf("tenantkeys: mode must be %q or %q", ModeManaged, ModeBYOK)
	}
	if strings.TrimSpace(actor) == "" {
		return nil, errors.New("tenantkeys: rotation audit actor is required")
	}
	if mode == ModeBYOK && strings.TrimSpace(byokRef) == "" {
		return nil, errors.New("tenantkeys: byok reference is required")
	}

	if mode == ModeBYOK {
		// AUTHZ-10: the reference is untrusted tenant input resolved with the
		// deployment's own secret-store credentials. Fence it to the operator-
		// configured per-tenant namespace BEFORE resolving (confused-deputy /
		// SSRF guard), then require it to resolve to valid material (the lockout
		// guard). Every rejection — policy OR resolution — surfaces the single
		// generic tenantcrypto.ErrBYOKRefRejected; the reason is logged server
		// side only so the surface is not an existence oracle (G7-1, G7-6).
		if reason := k.refPolicy.reject(tenantID, byokRef); reason != "" {
			k.logBYOKReject(tenantID, reason)
			return nil, tenantcrypto.ErrBYOKRefRejected
		}
		if err := k.validateBYOKReference(ctx, tenantID, byokRef); err != nil {
			return nil, err
		}
	}

	at := k.now().UTC()
	var managedKEK []byte
	var err error
	if mode == ModeManaged {
		managedKEK, err = crypto.Random(32)
		if err != nil {
			return nil, err
		}
	}
	cached := false
	defer func() {
		if len(managedKEK) > 0 && !cached {
			zeroize(managedKEK)
		}
	}()

	kv, err := k.store.RotateAtomic(ctx, tenantID, actor, at, func(ctx context.Context, next int) (KeyVersion, error) {
		v := KeyVersion{
			TenantID: tenantID, Version: next, Mode: mode, State: StateActive,
			BYOKRef: byokRef, CreatedAt: at,
		}
		if mode == ModeManaged {
			sealed, err := k.master.Seal(ctx, managedKEK, []byte("tenant-kek:"+tenantID+":"+strconv.Itoa(next)))
			if err != nil {
				return KeyVersion{}, err
			}
			v.WrappedKEK = encodeSealed(sealed)
			v.BYOKRef = ""
		}
		return v, nil
	})
	if err != nil {
		if errors.Is(err, ErrKeyDestroyed) {
			return nil, ErrKeyDestroyed
		}
		return nil, fmt.Errorf("%w: %v", ErrRotationCommit, err)
	}

	// Do not expose a successor through the cache until its transaction is
	// confirmed committed. Purging after commit also removes every retired
	// version's raw bytes.
	k.purgeTenant(tenantID)
	if mode == ModeManaged {
		cached = k.cachePut(tenantID, kv.Version, ModeManaged, managedKEK)
	}
	return kv, nil
}

// validateBYOKReference resolves and decodes a customer key without populating
// the key cache. Rotation validation must be side-effect free: a transaction
// failure cannot leave an uncommitted successor's raw bytes cached. The caller
// has already fenced the reference with the BYOK ref policy (AUTHZ-10); a
// resolution/decode failure here returns the SAME generic rejection as a policy
// failure (reason logged server side only), so a dead reference is not
// distinguishable from a forbidden one at the API boundary.
func (k *Keyring) validateBYOKReference(ctx context.Context, tenantID, ref string) error {
	if k.resolve == nil {
		k.logBYOKReject(tenantID, "no secret-reference resolver is configured for byok")
		return tenantcrypto.ErrBYOKRefRejected
	}
	material, cleanup, err := k.resolve(ctx, ref)
	if err != nil {
		k.logBYOKReject(tenantID, "reference did not resolve")
		return tenantcrypto.ErrBYOKRefRejected
	}
	if cleanup != nil {
		defer cleanup()
	}
	trimmed := bytes.TrimSpace(material)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(decoded, trimmed)
	defer zeroize(decoded)
	if err != nil || n != 32 {
		k.logBYOKReject(tenantID, "resolved material is not base64 of exactly 32 bytes")
		return tenantcrypto.ErrBYOKRefRejected
	}
	return nil
}

// logBYOKReject records the SERVER-SIDE reason a tenant BYOK reference was
// refused. It never logs the reference value or resolved material (G7-6); the
// reason is always a fixed category string authored here, never tenant input.
func (k *Keyring) logBYOKReject(tenantID, reason string) {
	logger := k.log
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("byok reference rejected (AUTHZ-10)", "tenant_id", tenantID, "reason", reason)
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
