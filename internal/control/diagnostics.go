// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/hex"
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
	databaseCheck := support.PingCheck("database", nil)
	if s.pinger != nil {
		databaseCheck = support.PingCheck("database", func(ctx context.Context) error {
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			return s.pinger.Ping(c)
		})
	}
	checks := map[string]support.CheckFunc{
		"database": func(ctx context.Context) support.Check {
			check := databaseCheck(ctx)
			if check.Status != support.StatusOK {
				check.Finding = support.NewReadinessFinding(
					"readiness.database",
					"Database writer is unavailable",
					"The local writer database ping did not complete successfully; connection details are redacted.",
					support.LocalAction{Label: "Download redacted support bundle", Href: "/v1/diagnostics/bundle", Kind: support.ActionDownload},
				)
			}
			return check
		},
		"alert_evaluator": func(context.Context) support.Check {
			health := s.alertingHealth()
			if health.EvaluatorRunning {
				return support.Check{Status: support.StatusOK, Detail: health.Detail}
			}
			return support.Check{
				Status: support.StatusDegraded,
				Detail: health.Detail + "; setup: " + health.Setup,
				Finding: support.NewReadinessFinding(
					"readiness.alert_evaluator",
					"Alert rules are not being evaluated",
					"The local alert evaluator is inactive, so stored rules cannot create active alerts.",
					support.LocalAction{Label: "Review alert setup", Href: "/alerts", Kind: support.ActionNavigate},
				),
			}
		},
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
			check := support.Check{Status: st, Detail: detail}
			if st != support.StatusOK {
				check.Finding = support.NewReadinessFinding(
					"readiness.secrets_resolver",
					"A configured secret backend is unavailable",
					"The local resolver reports a failure newer than its last successful read; secret values are not included.",
					support.LocalAction{Label: "Download redacted support bundle", Href: "/v1/diagnostics/bundle", Kind: support.ActionDownload},
				)
			}
			return check
		}
	}
	// Multi-region cluster (S-EE2): degraded while writes are fenced.
	if s.cluster != nil {
		checks["cluster"] = func(context.Context) support.Check {
			if ok, _ := s.cluster.WriterUsable(); !ok {
				return support.Check{
					Status: support.StatusDegraded,
					Detail: "writes are fenced while the local writer is not usable",
					Finding: support.NewReadinessFinding(
						"readiness.cluster",
						"Control-plane writes are temporarily fenced",
						"The local cluster check cannot prove that the configured writer is the current writable primary.",
						support.LocalAction{Label: "Download redacted support bundle", Href: "/v1/diagnostics/bundle", Kind: support.ActionDownload},
					),
				}
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
				return support.Check{
					Status: support.StatusDegraded,
					Detail: "license expired — read-only",
					Finding: support.NewReadinessFinding(
						"readiness.license",
						"Commercial configuration is read-only",
						"The offline-verified license is past its grace period; telemetry pipelines continue running.",
						support.LocalAction{Label: "Review edition state", Href: "/admin#editions", Kind: support.ActionNavigate},
					),
				}
			case "grace":
				return support.Check{
					Status: support.StatusDegraded,
					Detail: "license expired — grace period",
					Finding: support.NewReadinessFinding(
						"readiness.license",
						"Commercial license is in its grace period",
						"The offline-verified license has expired and will become read-only after the local grace period.",
						support.LocalAction{Label: "Review edition state", Href: "/admin#editions", Kind: support.ActionNavigate},
					),
				}
			default:
				return support.Check{Status: support.StatusOK, Detail: string(info.Tier)}
			}
		}
	}
	return support.RunChecks(ctx, checks, time.Now)
}

// diagnosticsResponse is the admin-only native self-observability contract.
// The deployment-local fields contain no tenant identity or telemetry.
type diagnosticsResponse struct {
	support.Health
	SelfMetrics support.SelfMetrics `json:"self_metrics"`
	Build       version.Info        `json:"build"`
}

// diagnosticsSnapshot collects health, local process metrics, and build
// identity in one response. The same process metrics collector feeds the
// support bundle and protocol-compatible TSDB output.
func (s *Server) diagnosticsSnapshot(ctx context.Context) diagnosticsResponse {
	return diagnosticsResponse{
		Health:      s.deepHealth(ctx),
		SelfMetrics: support.CollectSelfMetrics(s.startedAt),
		Build:       version.Get(),
	}
}

// handleDiagnostics serves GET /v1/diagnostics — the admin-only deep-health
// and deployment-local self-observability report.
func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, s.diagnosticsSnapshot(r.Context()))
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
