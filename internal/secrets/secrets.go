// Package secrets is the S41 (F31) secret-backend integration: device/source/
// integration credentials resolve from enterprise secret stores instead of
// living in config files or long-lived env plaintext.
//
// # The contract
//
// A credential VALUE anywhere probectl accepts one may be a secret REFERENCE:
//
//	env:NAME                                 process environment
//	vault:<mount>/<path>#<field>             HashiCorp Vault KV v2
//	cyberark:<query>                         CyberArk CCP (Central Credential Provider)
//	aws:<secret-id>[#<json-field>]           AWS Secrets Manager (SigV4, no SDK)
//	azure:<vault-name>/<secret-name>         Azure Key Vault (client-credentials)
//	gcp:<project>/<secret>[/<version>]       GCP Secret Manager (service-account JWT)
//	literal:<value>                          escape hatch (a value starting with a scheme)
//
// Anything else is a literal. Backend access settings (addresses, role IDs,
// client credentials) come from the ENVIRONMENT only — never probectl config
// files — and every backend call rides TLS with certificate verification
// (CLAUDE.md §7 guardrail 12).
//
// # Guardrails (§7: 1, 3, 6; the S41 'watch out for')
//
//   - Fail closed: an unresolvable reference is an error, never an empty or
//     partial credential.
//   - No plaintext at rest: references resolve in memory at use time; resolved
//     values are cached ONLY encrypted (AES-256-GCM via the internal/crypto
//     provider, a per-process ephemeral key) and only for the lease TTL.
//   - Short-lived leases: cache entries expire (default 5m) and re-resolve, so
//     rotated upstream secrets are picked up without restarts.
//   - Redaction: errors and health snapshots never contain secret material;
//     reference strings are shown with their fragment redacted.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Ref is one parsed secret reference.
type Ref struct {
	Scheme string // "env", "vault", "cyberark", "aws", "azure", "gcp"
	Path   string // backend-specific locator (no field/fragment)
	Field  string // optional sub-field (#fragment)
}

// Redacted renders the reference for logs/health: locator yes, fragment
// REDACTED (fields can leak key names like "password"; cheap to hide).
func (r Ref) Redacted() string {
	if r.Field == "" {
		return r.Scheme + ":" + r.Path
	}
	return r.Scheme + ":" + r.Path + "#…"
}

// schemes the resolver recognizes (a value with any other prefix is literal).
var schemes = map[string]bool{"env": true, "vault": true, "cyberark": true, "aws": true, "azure": true, "gcp": true}

// IsRef reports whether raw is a secret reference (vs a literal value).
func IsRef(raw string) bool {
	if strings.HasPrefix(raw, "literal:") {
		return false
	}
	i := strings.IndexByte(raw, ':')
	return i > 0 && schemes[raw[:i]]
}

// Parse splits a reference. Call IsRef first; Parse fails on non-references.
func Parse(raw string) (Ref, error) {
	if !IsRef(raw) {
		return Ref{}, fmt.Errorf("secrets: %q is not a secret reference", raw)
	}
	i := strings.IndexByte(raw, ':')
	ref := Ref{Scheme: raw[:i]}
	rest := raw[i+1:]
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		ref.Path, ref.Field = rest[:j], rest[j+1:]
	} else {
		ref.Path = rest
	}
	if ref.Path == "" {
		return Ref{}, fmt.Errorf("secrets: empty path in %s reference", ref.Scheme)
	}
	return ref, nil
}

// Source fetches one secret from one backend. Implementations never log the
// returned value and return redacted errors.
type Source interface {
	Scheme() string
	Fetch(ctx context.Context, ref Ref) (string, error)
}

// ErrUnavailable wraps backend-unreachable failures (still fail-closed — the
// caller gets an error, never a guess; the sentinel only aids health/ops).
var ErrUnavailable = errors.New("secrets: backend unavailable")

// DefaultLease bounds how long a resolved value may be served from cache
// before re-resolving (the short-lived-lease behavior).
const DefaultLease = 5 * time.Minute

type cacheEntry struct {
	sealed  []byte // AES-256-GCM via internal/crypto — never plaintext at rest
	expires time.Time
}

// BackendHealth is one backend's operational snapshot (no secret material).
type BackendHealth struct {
	Scheme       string    `json:"scheme"`
	Configured   bool      `json:"configured"`
	Resolves     int       `json:"resolves"`
	Failures     int       `json:"failures"`
	LastOK       time.Time `json:"last_ok,omitempty"`
	LastError    string    `json:"last_error,omitempty"` // redacted message
	LastErrorAt  time.Time `json:"last_error_at,omitempty"`
	CachedLeases int       `json:"cached_leases"`
}

// Resolver routes references to backends with sealed, lease-bound caching.
type Resolver struct {
	mu       sync.Mutex
	backends map[string]Source
	cache    map[string]cacheEntry
	stats    map[string]*BackendHealth
	lease    time.Duration
	key      []byte // ephemeral per-process cache key
	clock    func() time.Time
}

// NewResolver builds a resolver over the given backends. lease <= 0 takes
// DefaultLease.
func NewResolver(lease time.Duration, backends ...Source) (*Resolver, error) {
	if lease <= 0 {
		lease = DefaultLease
	}
	key, err := crypto.Default.Random(32)
	if err != nil {
		return nil, fmt.Errorf("secrets: cache key: %w", err)
	}
	r := &Resolver{
		backends: map[string]Source{},
		cache:    map[string]cacheEntry{},
		stats:    map[string]*BackendHealth{},
		lease:    lease,
		key:      key,
		clock:    time.Now,
	}
	for _, b := range backends {
		r.backends[b.Scheme()] = b
		r.stats[b.Scheme()] = &BackendHealth{Scheme: b.Scheme(), Configured: true}
	}
	return r, nil
}

// Resolve returns the value for raw: literals pass through (with the
// "literal:" escape stripped), references resolve via their backend. Fails
// closed on unknown schemes, unconfigured backends, and backend errors.
func (r *Resolver) Resolve(ctx context.Context, raw string) (string, error) {
	if !IsRef(raw) {
		return strings.TrimPrefix(raw, "literal:"), nil
	}
	ref, err := Parse(raw)
	if err != nil {
		return "", err
	}
	now := r.clock()

	r.mu.Lock()
	if e, ok := r.cache[raw]; ok && now.Before(e.expires) {
		plain, derr := crypto.Default.Decrypt(r.key, e.sealed, []byte(raw))
		r.mu.Unlock()
		if derr != nil {
			return "", fmt.Errorf("secrets: cache unseal %s: %w", ref.Redacted(), derr)
		}
		return string(plain), nil
	}
	src := r.backends[ref.Scheme]
	st := r.stats[ref.Scheme]
	r.mu.Unlock()

	if src == nil {
		return "", fmt.Errorf("secrets: %s backend not configured (reference %s)", ref.Scheme, ref.Redacted())
	}
	value, ferr := src.Fetch(ctx, ref)

	r.mu.Lock()
	defer r.mu.Unlock()
	if ferr != nil {
		st.Failures++
		st.LastError = ferr.Error()
		st.LastErrorAt = now
		// Fail closed: no stale fallback for credentials — a rotated-away secret
		// must stop being used (the S41 'watch out for').
		delete(r.cache, raw)
		return "", fmt.Errorf("secrets: resolve %s: %w", ref.Redacted(), ferr)
	}
	st.Resolves++
	st.LastOK = now
	sealed, serr := crypto.Default.Encrypt(r.key, []byte(value), []byte(raw))
	if serr == nil {
		r.cache[raw] = cacheEntry{sealed: sealed, expires: now.Add(r.lease)}
	}
	return value, nil
}

// Health returns per-backend snapshots (sorted, no secret material).
func (r *Resolver) Health() []BackendHealth {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock()
	live := map[string]int{}
	for raw, e := range r.cache {
		if now.Before(e.expires) {
			if ref, err := Parse(raw); err == nil {
				live[ref.Scheme]++
			}
		}
	}
	out := make([]BackendHealth, 0, len(r.stats))
	for scheme, st := range r.stats {
		h := *st
		h.CachedLeases = live[scheme]
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scheme < out[j].Scheme })
	return out
}

// Schemes lists the configured backend schemes (sorted).
func (r *Resolver) Schemes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.backends))
	for s := range r.backends {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
