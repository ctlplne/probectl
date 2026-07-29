// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/ai/mcp"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/remediation"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// NewMCPServer builds probectl's MCP server (S25) over the tenant-scoped stores,
// the S23 query engine, and the S24 RCA analyzer. The tools are read-only; the
// tenant boundary, RBAC, and tenant ABAC deny policies are enforced at the MCP
// layer, with tenant + RBAC enforced again at the engine/stores (defense in
// depth).
func NewMCPServer(
	cfg *config.Config,
	log *slog.Logger,
	pool *pgxpool.Pool,
	pathStore pathstore.Store,
	ratePerMin int,
	aiGate *ai.EgressGate,
	gate *fairness.Gate,
	remed remediation.Service,
	sources ...AISources,
) *mcp.Server {
	return newMCPServer(cfg, log, pool, pathStore, ratePerMin, aiGate, gate, remed, nil, sources...)
}

// NewMCPServerWithPolicyLoader builds the colocated HTTP MCP transport with the
// control server's shared ABAC cache. Keeping this separate preserves the
// ordinary constructor while making production cache sharing explicit.
func NewMCPServerWithPolicyLoader(
	cfg *config.Config,
	log *slog.Logger,
	pool *pgxpool.Pool,
	pathStore pathstore.Store,
	ratePerMin int,
	aiGate *ai.EgressGate,
	gate *fairness.Gate,
	remed remediation.Service,
	policyLoader mcp.PolicyLoader,
	sources ...AISources,
) *mcp.Server {
	return newMCPServer(cfg, log, pool, pathStore, ratePerMin, aiGate, gate, remed, policyLoader, sources...)
}

func newMCPServer(
	cfg *config.Config,
	log *slog.Logger,
	pool *pgxpool.Pool,
	pathStore pathstore.Store,
	ratePerMin int,
	aiGate *ai.EgressGate,
	gate *fairness.Gate,
	remed remediation.Service,
	policyLoader mcp.PolicyLoader,
	sources ...AISources,
) *mcp.Server {
	if aiGate == nil {
		panic("control.NewMCPServer requires the shared AI egress gate")
	}
	if policyLoader == nil {
		if pool == nil {
			policyLoader = func(context.Context, string) ([]auth.Policy, error) {
				return nil, errors.New("MCP ABAC policy store is unavailable")
			}
		} else {
			policyLoader = newABACCache(pool).policies
		}
	}
	src := firstAISources(sources)
	backend := mcpBackend{
		pool:        pool,
		engine:      buildEngineWithPolicyLoader(cfg, pool, policyLoader, src),
		analyzer:    buildAnalyzerWithPolicyLoader(cfg, log, pool, aiGate, policyLoader, src),
		pathStore:   pathStore,
		gate:        gate,
		remediation: remed,
	}
	// AIRCA-001/003: every tool call is consent-gated + redacted by the
	// caller-provided egress gate and audited to the tenant stream — including
	// denials. In the HTTP server this is the same pointer RCA and authoring use.
	return mcp.New(backend, aiGate,
		mcp.WithRateLimit(ratePerMin), mcp.WithLogger(log),
		mcp.WithPolicyLoader(policyLoader),
		mcp.WithCallAudit(mcpCallAuditor(pool, log)))
}

// MCPPolicyLoader exposes the HTTP control plane's ABAC cache to the colocated
// MCP transport. Policy CRUD invalidation therefore takes effect on both
// surfaces immediately; standalone MCP builds their own cache in NewMCPServer.
func (s *Server) MCPPolicyLoader() mcp.PolicyLoader {
	if s == nil || s.abac == nil {
		return nil
	}
	return s.abac.policies
}

// mcpCallAuditor appends mcp.tool_call to the tenant's tamper-evident audit
// stream: who called which tool and the outcome (AIRCA-003). Best-effort —
// the log line always lands; the DB append never blocks the call path.
func mcpCallAuditor(pool *pgxpool.Pool, log *slog.Logger) mcp.CallAudit {
	return func(ctx context.Context, ev mcp.CallEvent) {
		log.Info("mcp tool call", "tenant_id", ev.TenantID, "user_id", ev.UserID,
			"tool", ev.Tool, "allowed", ev.Allowed, "denial", ev.Denial)
		if pool == nil {
			return
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(ev.TenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			actor := ev.UserID
			if actor == "" {
				actor = "mcp-client"
			}
			_, err := audit.TenantAppend(ctx, sc, actor, "mcp.tool_call", ev.Tool, map[string]any{
				"allowed": ev.Allowed, "denial": ev.Denial,
			})
			return err
		}); err != nil {
			// CODE-002: surface a failed MCP-call audit write (the call already happened).
			log.Warn("failed to persist mcp.tool_call audit record", "tenant_id", ev.TenantID, "tool", ev.Tool, "error", err.Error())
		}
	}
}

// mcpBackend implements mcp.Backend over the control-plane data sources. Every
// method scopes to the principal's tenant (the engine/stores enforce it), so a
// tool can never reach another tenant's data.
type mcpBackend struct {
	pool        *pgxpool.Pool
	engine      *ai.Engine
	analyzer    *ai.Analyzer
	pathStore   pathstore.Store
	gate        *fairness.Gate      // per-tenant query-cost guard (S-T7); nil = unbounded
	remediation remediation.Service // S-EE5 propose-only; nil = feature unlicensed
}

// beginQuery applies the per-tenant query-cost guard to the expensive MCP
// tools (the deployment-wide MCP rate limit still applies first). The
// returned release is never nil.
func (b mcpBackend) beginQuery(ctx context.Context, p *auth.Principal) (func(), error) {
	if b.gate == nil || p == nil {
		return func() {}, nil
	}
	return b.gate.BeginQuery(ctx, p.TenantID)
}

func (b mcpBackend) scope(ctx context.Context, p *auth.Principal, fn func(context.Context, tenancy.Scope) error) error {
	return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(p.TenantID)), b.pool, fn)
}

func (b mcpBackend) ListTests(ctx context.Context, p *auth.Principal) (any, error) {
	var tests []store.Test
	if err := b.scope(ctx, p, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.ListAll(ctx, sc, 0)
		tests = t
		return e
	}); err != nil {
		return nil, err
	}
	return map[string]any{"tests": tests}, nil
}

func (b mcpBackend) GetPath(ctx context.Context, p *auth.Principal, target string) (any, error) {
	pth, ok, err := b.pathStore.Latest(ctx, p.TenantID, target)
	if err != nil {
		return nil, err
	}
	if !ok {
		return map[string]any{"found": false, "target": target}, nil
	}
	return map[string]any{"found": true, "path": pth}, nil
}

func (b mcpBackend) GetIncident(ctx context.Context, p *auth.Principal, id string) (any, error) {
	inc, err := b.incident(ctx, p, id)
	if err != nil {
		return nil, err
	}
	return inc, nil
}

func (b mcpBackend) CorrelateIncident(ctx context.Context, p *auth.Principal, id string) (any, error) {
	inc, err := b.incident(ctx, p, id)
	if err != nil {
		return nil, err
	}
	// The incident IS the cross-plane correlation (S17): summarize which planes
	// contributed alongside the full timeline.
	planes := map[string]int{}
	for _, sig := range inc.Signals {
		planes[sig.Plane]++
	}
	return map[string]any{"incident": inc, "planes": planes, "signal_count": len(inc.Signals)}, nil
}

func (b mcpBackend) incident(ctx context.Context, p *auth.Principal, id string) (*incident.Incident, error) {
	var inc *incident.Incident
	err := b.scope(ctx, p, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Incidents{}.Get(ctx, sc, id)
		inc = x
		return e
	})
	return inc, err
}

func (b mcpBackend) GetBGPEvents(ctx context.Context, p *auth.Principal, prefix, asn string, limit int) (any, error) {
	return b.queryEvents(ctx, p, map[string]string{"type": "bgp", "prefix": prefix, "asn": asn}, limit)
}

func (b mcpBackend) QueryFlows(ctx context.Context, p *auth.Principal, service, src, dst string, limit int) (any, error) {
	return b.queryEvents(ctx, p, map[string]string{"type": "flow", "service": service, "src": src, "dst": dst}, limit)
}

// queryEvents goes through the S23 engine (events domain) — source RBAC+ABAC is
// checked again — and degrades gracefully when the events store is not wired in
// this deployment.
func (b mcpBackend) queryEvents(ctx context.Context, p *auth.Principal, sel map[string]string, limit int) (any, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	clean := map[string]string{}
	for k, v := range sel {
		if v != "" {
			clean[k] = v
		}
	}
	release, err := b.beginQuery(ctx, p) // fairness (S-T7)
	if err != nil {
		return nil, err
	}
	defer release()
	res, err := b.engine.Query(ctx, p, ai.Query{Domain: ai.DomainEvents, Selector: clean, Limit: limit})
	if err != nil {
		if errors.Is(err, ai.ErrNoSource) {
			return map[string]any{"events": []any{}, "note": "the events store is not configured in this deployment"}, nil
		}
		return nil, err
	}
	return map[string]any{"events": res.Rows, "truncated": res.Truncated}, nil
}

func (b mcpBackend) ExplainDegradation(ctx context.Context, p *auth.Principal, question string, subject map[string]string) (any, error) {
	return b.analyzer.Analyze(ctx, p, ai.Question{Text: question, Subject: subject})
}

// NewMCPAuthenticator resolves a control-plane bearer token to a principal: the
// token's tenant plus the owning user's effective permissions and ABAC subject
// attributes (RLS-scoped). The token lookup is pre-tenant (the token determines
// the tenant), like sessions.
func NewMCPAuthenticator(pool *pgxpool.Pool) mcp.Authenticator { return mcpAuthenticator{pool: pool} }

type mcpAuthenticator struct{ pool *pgxpool.Pool }

func (a mcpAuthenticator) Authenticate(ctx context.Context, bearer string) (*auth.Principal, error) {
	tenantID, userID, err := store.NewMCPTokens(a.pool).Authenticate(ctx, crypto.Hash([]byte(bearer)))
	if err != nil {
		return nil, err
	}
	perms, err := permLoader(a).ForUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(perms))
	for _, k := range perms {
		m[k] = true
	}
	p := &auth.Principal{TenantID: tenantID, UserID: userID, Permissions: m}
	attrs := map[string]string{"mfa": boolStr(p.MFASatisfied)}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), a.pool, func(ctx context.Context, sc tenancy.Scope) error {
		u, err := (store.Users{}).Get(ctx, sc, userID)
		if err != nil {
			return err
		}
		p.Email = u.Email
		p.DisplayName = u.DisplayName
		for k, v := range u.Attributes {
			attrs[k] = v
		}
		return nil
	}); err != nil {
		return nil, err
	}
	p.Attributes = attrs
	return p, nil
}

// ProposeRemediation implements the proposal-only MCP tool (S-EE5). It
// delegates to the remediation Service, which ALWAYS creates a state=proposed
// proposal — this path can never approve or execute. When the feature is
// unlicensed (no service installed), the tool errors. The proposer is recorded
// as the AI, distinct from a human approver.
func (b mcpBackend) ProposeRemediation(ctx context.Context, p *auth.Principal, kind, title, rationale, target, incidentID string) (any, error) {
	if b.remediation == nil {
		return nil, errors.New("remediation is not enabled in this deployment")
	}
	return b.remediation.Propose(ctx, p.TenantID, "ai:propose_remediation", remediation.ProposeInput{
		Kind: remediation.Kind(kind), Title: title, Rationale: rationale,
		Target: target, IncidentID: incidentID,
	})
}
