// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

// Package provider is the probectl provider/management plane (S-T1, F51):
// the MSP operator surface for tenant lifecycle (provision / configure /
// suspend / offboard), fleet-across-tenants health, and audited break-glass.
//
// The privilege model (CLAUDE.md §7 guardrail 1):
//   - Operators are a privilege domain DISTINCT from tenant users: their own
//     accounts, mandatory TOTP MFA, their own sessions, their own audit
//     stream (audit.ProviderAppend).
//   - Operators get NO implicit read access to tenant telemetry. The storage
//     layer itself enforces this: every provider query runs as the
//     probectl_provider role (tenancy.InProvider), whose only telemetry-table
//     grant is SELECT over agents via an explicit fleet policy.
//   - The ONLY path to tenant telemetry is an explicit, time-bounded,
//     tenant-CONSENTED break-glass grant, and every single access through it
//     is written to the provider audit stream before data is returned.
//
// This package is attached to the core server as an opaque http.Handler at
// the main.go seam, gated by license.FeatureProviderPlane — core never
// imports it.
package provider

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Deps are the core seams the provider plane builds on. Everything here is a
// CORE type — the one-way import rule in action.
type Deps struct {
	Pool     *pgxpool.Pool
	License  *license.Manager
	Log      *slog.Logger
	Results  *control.LatestResults // the S-T1 break-glass telemetry surface
	Sessions *auth.Manager          // tenant sessions (the consent leg); nil = consent 503s
	Perms    auth.PermissionLoader  // tenant RBAC (the consent permission check)
	// IRSidecar owns only public wrapping capability. Protected break-glass
	// mutations fail closed if this local encrypted sidecar is unavailable.
	IRSidecar audit.IRStageAppender
	// S-T2: the silo capability (nil unless siloed_isolation is licensed —
	// then only pooled tenants can be provisioned) + the isolation router's
	// cache-invalidation hook for lifecycle changes.
	Silo           SiloOps
	SiloInvalidate func()
	// S-T3: the metering capability (nil unless the metering feature is
	// licensed — then the usage/quota surfaces stay hidden).
	Metering *Metering
	// S-T5: the CORE tenant-lifecycle engine (export/erasure is a compliance
	// right; the provider plane only adds the operator-facing erase view).
	Lifecycle Lifecycle
	// S-T7: the CORE fairness gate + policy store (operator views/tuning;
	// enforcement itself is core in every edition).
	Fairness *Fairness
	// S-EE3: the data-governance policy store + composed view (governance feat).
	Governance *Governance
}

// Build constructs the provider plane handler. It fails loudly on missing
// hard requirements (fail closed on configuration): a database pool and the
// envelope key — TOTP secrets are sealed at rest, so a provider deployment
// without PROBECTL_ENVELOPE_KEY is a misconfiguration, not a shrug.
func Build(cfg *config.Config, d Deps) (http.Handler, error) {
	if d.Pool == nil {
		return nil, errors.New("provider: a database pool is required")
	}
	if d.License == nil {
		return nil, errors.New("provider: the license manager is required")
	}
	if d.IRSidecar == nil {
		return nil, errors.New("provider: encrypted IR attribution sidecar is required")
	}
	if cfg.EnvelopeKey == "" {
		return nil, errors.New("provider: PROBECTL_ENVELOPE_KEY is required (operator TOTP secrets are envelope-sealed at rest)")
	}
	kek, err := crypto.NewStaticKeyProviderFromBase64(cfg.EnvelopeKeyID, cfg.EnvelopeKey)
	if err != nil {
		return nil, err
	}
	env := crypto.NewEnvelope(kek)

	st := NewPGStore(d.Pool)
	sink := &providerAudit{pool: d.Pool, ir: d.IRSidecar}
	var telemetry TelemetryReader
	if d.Results != nil {
		telemetry = latestResultsReader{lr: d.Results}
	}
	svc, err := NewService(st, sink, d.License, telemetry, env,
		time.Duration(cfg.ProviderBreakGlassMaxTTLMinutes)*time.Minute)
	if err != nil {
		return nil, err
	}
	if d.Silo != nil {
		svc.WithSilo(d.Silo, d.SiloInvalidate)
	}

	var tenantAuth TenantAuth
	if d.Sessions != nil && d.Perms != nil {
		tenantAuth = coreTenantAuth{sessions: d.Sessions, perms: d.Perms, pool: d.Pool}
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return NewHandler(svc, NewSessions(cfg.SessionHMACKey).WithIdleTimeout(cfg.SessionIdleTimeout), tenantAuth, log,
		cfg.ProviderBootstrapToken, cfg.CookieSecure()).
		WithMetering(d.Metering).WithLifecycle(d.Lifecycle).
		WithFairness(d.Fairness).WithGovernance(d.Governance), nil
}

// providerAudit writes the separate, tamper-evident provider audit stream.
// Break-glass actions use the typed same-transaction IR seam; a plain append is
// rejected by internal/audit for that namespace.
type providerAudit struct {
	pool *pgxpool.Pool
	ir   audit.IRStageAppender
}

func (a *providerAudit) Append(ctx context.Context, actor, action, target string, data map[string]any) error {
	_, err := audit.ProviderAppend(ctx, a.pool, actor, action, target, data)
	return err
}

func (a *providerAudit) AppendTx(ctx context.Context, q tenancy.Querier, actor, action, target string, data map[string]any) error {
	_, err := audit.ProviderAppendTx(ctx, q, actor, action, target, data)
	return err
}

func (a *providerAudit) AppendBreakGlass(
	ctx context.Context,
	actor, action, target string,
	data map[string]any,
	attribution audit.IRAttribution,
) error {
	_, err := audit.ProviderAppendBreakGlass(
		ctx,
		a.pool,
		a.ir,
		actor,
		action,
		target,
		data,
		attribution,
	)
	return err
}

func (a *providerAudit) AppendBreakGlassTx(
	ctx context.Context,
	q tenancy.Querier,
	actor, action, target string,
	data map[string]any,
	attribution audit.IRAttribution,
) error {
	_, err := audit.ProviderAppendBreakGlassTx(
		ctx,
		q,
		a.ir,
		actor,
		action,
		target,
		data,
		attribution,
	)
	return err
}

// latestResultsReader adapts the core latest-results read model.
type latestResultsReader struct{ lr *control.LatestResults }

func (r latestResultsReader) LatestResults(tenantID string) any { return r.lr.List(tenantID) }

// coreTenantAuth adapts the core session manager and tenant-scoped identity
// stores for break-glass consent. Consent is intentionally a fresh read rather
// than a cache hit: it is a rare, high-impact decision, and a policy or subject
// load failure must deny rather than silently becoming an empty policy set.
type coreTenantAuth struct {
	sessions *auth.Manager
	perms    auth.PermissionLoader
	pool     *pgxpool.Pool
}

func (c coreTenantAuth) ResolveSession(ctx context.Context, token string) (*auth.Session, error) {
	return c.sessions.Resolve(ctx, token)
}

func (c coreTenantAuth) AuthorizationContext(ctx context.Context, sess *auth.Session) (*auth.Principal, []auth.Policy, error) {
	if sess == nil || c.perms == nil || c.pool == nil {
		return nil, nil, errors.New("provider: incomplete tenant authorization dependencies")
	}

	grants, err := c.perms.ForUser(ctx, sess.TenantID, sess.UserID)
	if err != nil {
		return nil, nil, err
	}

	principal := auth.PrincipalWithPermissionGrants(&auth.Principal{
		TenantID:       sess.TenantID,
		UserID:         sess.UserID,
		Email:          sess.Email,
		DisplayName:    sess.DisplayName,
		MFASatisfied:   sess.MFASatisfied,
		TimeZone:       sess.TimeZone,
		Locale:         sess.Locale,
		TenantTimeZone: sess.TenantTimeZone,
		TenantLocale:   sess.TenantLocale,
	}, grants)
	var policies []auth.Policy
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(sess.TenantID)), c.pool, func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (store.Users{}).Get(ctx, sc, sess.UserID)
		if err != nil {
			return err
		}
		// RLS is the primary boundary. Keep an explicit equality check as a
		// second lock so a misconfigured store can never hand another tenant's
		// subject attributes to this consent decision.
		if user.TenantID != sess.TenantID {
			return errors.New("provider: tenant authorization subject mismatch")
		}
		principal.Email = user.Email
		principal.DisplayName = user.DisplayName
		principal.Attributes = make(map[string]string, len(user.Attributes)+1)
		for key, value := range user.Attributes {
			principal.Attributes[key] = value
		}
		// MFA is derived from the authenticated session, never trusted from a
		// mutable SCIM subject attribute.
		if sess.MFASatisfied {
			principal.Attributes["mfa"] = "true"
		} else {
			principal.Attributes["mfa"] = "false"
		}

		policies, err = (store.ABACPolicies{}).List(ctx, sc)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return principal, policies, nil
}
