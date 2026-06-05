// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
// See ee/doc.go for the boundary rules every ee/ file observes.

// Package whitelabel is per-tenant white-label branding (S-T4, F54-full),
// unlocked by the white_label license feature: per-tenant (and
// provider-master) overrides of the S8a design tokens, logo, product name,
// branded login, custom-domain mapping, and branded email templates —
// resolved at runtime per tenant, never a per-screen retrofit (the S8a token
// contract is the whole mechanism).
//
// The cardinal rule (the S-T4 regression): one tenant's brand must NEVER
// bleed into another's resolution. Every cache entry is keyed strictly by
// tenant (or exact host); a resolution failure degrades to the DEFAULT
// brand, never to another tenant's.
package whitelabel

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/branding"
)

// Record is one stored brand (tenant or provider master). Empty fields fall
// through to the next precedence level at resolution time.
type Record struct {
	TenantID       string            `json:"tenant_id,omitempty"` // "" = provider master
	ProductName    string            `json:"product_name"`
	LogoDataURI    string            `json:"logo_data_uri,omitempty"`
	LoginMessage   string            `json:"login_message,omitempty"`
	TokenOverrides map[string]string `json:"token_overrides,omitempty"`
	EmailFromName  string            `json:"email_from_name,omitempty"`
	EmailFooter    string            `json:"email_footer,omitempty"`
	CustomDomain   string            `json:"custom_domain,omitempty"` // tenant rows only
	UpdatedBy      string            `json:"updated_by,omitempty"`
}

// Validate applies the core branding contract to a record.
func (r Record) Validate() error {
	if err := branding.ValidateOverrides(r.TokenOverrides); err != nil {
		return err
	}
	if err := branding.ValidateLogo(r.LogoDataURI); err != nil {
		return err
	}
	return branding.ValidateDomain(r.CustomDomain)
}

// Store persists brands.
type Store interface {
	// TenantBrand returns a tenant's brand row (nil = none).
	TenantBrand(ctx context.Context, tenantID string) (*Record, error)
	// TenantByDomain resolves a custom domain to its brand row (nil = none).
	TenantByDomain(ctx context.Context, host string) (*Record, error)
	// ProviderBrand returns the provider master (nil = none).
	ProviderBrand(ctx context.Context) (*Record, error)
	// SetTenantBrand upserts a tenant's brand.
	SetTenantBrand(ctx context.Context, rec Record) error
	// SetProviderBrand upserts the provider master.
	SetProviderBrand(ctx context.Context, rec Record) error
}

// Resolver implements branding.Source over a Store with a short TTL cache.
// Cache keys are STRICTLY per tenant ("t:<id>"), per host ("h:<host>"), or
// the provider master ("master") — the no-bleed property is structural.
type Resolver struct {
	store Store
	ttl   time.Duration
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	rec     *Record // nil = known-absent (negative cache)
	fetched time.Time
}

// NewResolver wires the resolver.
func NewResolver(store Store, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Resolver{store: store, ttl: ttl, now: time.Now, cache: map[string]cached{}}
}

// Invalidate drops the cache (after a branding write).
func (r *Resolver) Invalidate() {
	r.mu.Lock()
	r.cache = map[string]cached{}
	r.mu.Unlock()
}

func (r *Resolver) lookup(ctx context.Context, key string, fetch func(context.Context) (*Record, error)) *Record {
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && r.now().Sub(e.fetched) < r.ttl {
		r.mu.Unlock()
		return e.rec
	}
	r.mu.Unlock()
	rec, err := fetch(ctx)
	if err != nil {
		// Degrade to "absent" (→ the default brand), and do NOT cache the
		// failure long: branding must never take a login down, and must
		// never serve another tenant's brand as a fallback.
		return nil
	}
	r.mu.Lock()
	r.cache[key] = cached{rec: rec, fetched: r.now()}
	r.mu.Unlock()
	return rec
}

// For implements branding.Source: precedence tenant row → provider master →
// the probectl default. Host resolves to a tenant only via the EXACT
// custom-domain row.
func (r *Resolver) For(ctx context.Context, host, tenantID string) branding.Branding {
	var rec *Record
	switch {
	case tenantID != "":
		// A known tenant resolves by TENANT only — never by the serving
		// host. A signed-in tenant-B user on tenant A's domain must get B's
		// resolution (master/default), not A's brand (the no-bleed rule).
		rec = r.lookup(ctx, "t:"+tenantID, func(ctx context.Context) (*Record, error) {
			return r.store.TenantBrand(ctx, tenantID)
		})
	case host != "":
		// Pre-auth: the custom-domain mapping picks the brand.
		rec = r.lookup(ctx, "h:"+host, func(ctx context.Context) (*Record, error) {
			return r.store.TenantByDomain(ctx, host)
		})
	}
	master := r.lookup(ctx, "master", func(ctx context.Context) (*Record, error) {
		return r.store.ProviderBrand(ctx)
	})
	return merge(rec, master)
}

// TenantForHost implements branding.Source (custom-domain login).
func (r *Resolver) TenantForHost(ctx context.Context, host string) string {
	if host == "" {
		return ""
	}
	rec := r.lookup(ctx, "h:"+host, func(ctx context.Context) (*Record, error) {
		return r.store.TenantByDomain(ctx, host)
	})
	if rec == nil {
		return ""
	}
	return rec.TenantID
}

// merge folds tenant → master → default, field by field.
func merge(tenant, master *Record) branding.Branding {
	b := branding.Default()
	apply := func(rec *Record) {
		if rec == nil {
			return
		}
		if rec.ProductName != "" {
			b.ProductName = rec.ProductName
		}
		if rec.LogoDataURI != "" {
			b.LogoDataURI = rec.LogoDataURI
		}
		if rec.LoginMessage != "" {
			b.LoginMessage = rec.LoginMessage
		}
		if rec.EmailFromName != "" {
			b.EmailFromName = rec.EmailFromName
		}
		if rec.EmailFooter != "" {
			b.EmailFooter = rec.EmailFooter
		}
		for k, v := range rec.TokenOverrides {
			if b.TokenOverrides == nil {
				b.TokenOverrides = map[string]string{}
			}
			b.TokenOverrides[k] = v
		}
	}
	apply(master) // master first, tenant overrides on top
	apply(tenant)
	return b
}

// normalizeDomain canonicalizes a stored custom domain.
func normalizeDomain(d string) string { return branding.NormalizeHost(strings.TrimSpace(d)) }
