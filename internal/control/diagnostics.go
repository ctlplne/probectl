// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/support"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// Supportability (S-EE4, core): deep health checks + a secret-stripped support
// bundle for triage. Admin-only (`diagnostics.read`); the bundle never
// contains secrets, credentials, or PII (guardrail 6).

// deepHealth runs the registered component checks against the server's deps.
func (s *Server) deepHealth(ctx context.Context) support.Health {
	checks := map[string]support.CheckFunc{
		"database": support.PingCheck("database", func(ctx context.Context) error {
			if s.pinger == nil {
				return errors.New("not configured")
			}
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			return s.pinger.Ping(c)
		}),
	}
	// Secrets resolver (S41): degraded if any backend is failing.
	if s.secretsHealth != nil {
		checks["secrets_resolver"] = func(context.Context) support.Check {
			st := support.StatusOK
			detail := ""
			for _, b := range s.secretsHealth.Health() {
				if b.Failures > 0 && (b.LastOK.IsZero() || b.LastErrorAt.After(b.LastOK)) {
					st = support.StatusDegraded
					detail = "a secret backend is failing"
				}
			}
			return support.Check{Status: st, Detail: detail}
		}
	}
	// Multi-region cluster (S-EE2): degraded while writes are fenced.
	if s.cluster != nil {
		checks["cluster"] = func(context.Context) support.Check {
			if ok, reason := s.cluster.WriterUsable(); !ok {
				return support.Check{Status: support.StatusDegraded, Detail: reason}
			}
			return support.Check{Status: support.StatusOK}
		}
	}
	// License (S-T0): degraded once expired into read-only.
	if s.license != nil {
		checks["license"] = func(context.Context) support.Check {
			info := s.licenseManager().Info()
			switch string(info.State) {
			case "read_only":
				return support.Check{Status: support.StatusDegraded, Detail: "license expired — read-only"}
			case "grace":
				return support.Check{Status: support.StatusDegraded, Detail: "license expired — grace period"}
			default:
				return support.Check{Status: support.StatusOK, Detail: string(info.Tier)}
			}
		}
	}
	return support.RunChecks(ctx, checks, time.Now)
}

// handleDiagnostics serves GET /v1/diagnostics — the deep-health report.
func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, s.deepHealth(r.Context()))
	return nil
}

// handleDiagnosticsBundle streams the secret-stripped support bundle (tar.gz).
func (s *Server) handleDiagnosticsBundle(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	src := s.supportSources(r.Context())
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="probectl-support-bundle.tar.gz"`)
	if _, err := support.Generate(w, src); err != nil {
		s.log.Error("support bundle failed", "error", err.Error())
		return nil // headers committed; truncation is the signal
	}
	return nil
}

// supportSources assembles the bundle inputs from the server. Everything here
// is safe by construction: config.Redacted is an allowlist, the topology is
// anonymized counts, and the known secrets are passed as RedactValues so they
// are scrubbed from the assembled bytes (defense in depth).
func (s *Server) supportSources(ctx context.Context) support.Sources {
	return support.Sources{
		Version:        version.Get(),
		ConfigRedacted: s.cfg.Redacted(),
		Health:         s.deepHealth(ctx),
		SelfMetrics:    support.SelfSnapshot(s.startedAt),
		Topology:       s.topologySummary(ctx),
		Runtime:        support.CollectRuntime(s.startedAt),
		RedactValues:   s.knownSecrets(),
	}
}

// topologySummary returns ANONYMIZED deployment counts (no tenant identifiers
// or telemetry) via the provider role. Empty when there is no pool.
func (s *Server) topologySummary(ctx context.Context) support.TopologySummary {
	sum := support.TopologySummary{Region: s.cfg.Region, IsolationModels: map[string]int{}}
	if s.pool == nil {
		return sum
	}
	return topologySummaryFromProvider(ctx, sum, func(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
		return tenancy.InProvider(ctx, s.pool, fn)
	})
}

func topologySummaryFromProvider(ctx context.Context, sum support.TopologySummary, run func(context.Context, func(context.Context, tenancy.Querier) error) error) support.TopologySummary {
	markPartial := func(label string, err error) {
		sum.Partial = true
		sum.Errors = append(sum.Errors, label+": "+err.Error())
	}
	if err := run(ctx, func(ctx context.Context, q tenancy.Querier) error {
		if err := q.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&sum.Tenants); err != nil {
			markPartial("tenants_count", err)
		}
		if err := q.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&sum.Agents); err != nil {
			markPartial("agents_count", err)
		}
		rows, err := q.Query(ctx, `SELECT coalesce(isolation_model,'pooled'), count(*) FROM tenants GROUP BY 1`)
		if err != nil {
			markPartial("isolation_models", err)
		} else {
			defer rows.Close()
			for rows.Next() {
				var model string
				var n int
				if err := rows.Scan(&model, &n); err == nil {
					sum.IsolationModels[model] = n
				} else {
					markPartial("isolation_models_scan", err)
				}
			}
			if err := rows.Err(); err != nil {
				markPartial("isolation_models_rows", err)
			}
		}
		return nil
	}); err != nil {
		markPartial("provider_scope", err)
	}
	return sum
}

// knownSecrets gathers the deployment's sensitive config VALUES so the bundle
// scrubber can guarantee they never appear, even if a field were ever
// reflected by accident. Never logged, never returned to a client — only used
// as scrub targets.
func (s *Server) knownSecrets() []string {
	c := s.cfg
	cand := []string{
		c.EnvelopeKey, c.EnvelopeOpenerKeys, c.OIDCClientSecret, c.CMDBSecret, c.AIModelToken,
		c.OutageRadarToken, c.ProviderBootstrapToken, c.SIEMToken,
	}
	if len(c.SessionHMACKey) > 0 {
		cand = append(cand, hex.EncodeToString(c.SessionHMACKey))
	}
	for _, item := range strings.Split(c.EnvelopeOpenerKeys, ",") {
		_, keyB64, ok := strings.Cut(item, "=")
		if ok {
			cand = append(cand, strings.TrimSpace(keyB64))
		}
	}
	for tok := range c.OTLPTokens {
		cand = append(cand, tok)
	}
	if pw := dsnPassword(c.DatabaseURL); pw != "" {
		cand = append(cand, pw)
	}
	out := cand[:0]
	for _, v := range cand {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func dsnPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return ""
	}
	pw, _ := u.User.Password()
	return pw
}
