// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/support"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/version"
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
	// DPR-177: the intermediate that signs every agent SVID lives one year, and
	// the root that could replace it is deliberately offline. Nothing watched
	// the date, so a deployment's whole fleet stops a year after `agent-ca init`
	// — quietly, because each agent keeps working until its own leaf expires.
	// A date nobody is shown is a date nobody renews.
	if s.enrollSvc != nil {
		checks["agent_ca"] = func(context.Context) support.Check {
			notBefore, notAfter := s.enrollSvc.IssuingWindow()
			if notAfter.IsZero() {
				return support.Check{Status: support.StatusOK, Detail: "agent CA issuing window is not readable from this replica"}
			}
			now := time.Now()
			detail := "agent CA issuing intermediate valid until " + notAfter.UTC().Format(time.RFC3339)
			if now.Before(notAfter) && !pastIssuingRenewalPoint(notBefore, notAfter, now) {
				return support.Check{Status: support.StatusOK, Detail: detail}
			}
			title := "The agent CA must be renewed"
			body := "The intermediate that signs every agent identity expires " +
				notAfter.UTC().Format(time.RFC3339) + ". After that no agent can enroll or rotate, and the fleet stops within one SVID lifetime. Renewal needs the offline root key: probectl-control agent-ca renew -root-key <file>."
			if !now.Before(notAfter) {
				title = "The agent CA has expired"
				body = "The intermediate that signs every agent identity expired " +
					notAfter.UTC().Format(time.RFC3339) + ". Enrollment and rotation are refused until it is renewed with the offline root key: probectl-control agent-ca renew -root-key <file>."
			}
			return support.Check{
				Status: support.StatusDegraded,
				Detail: detail,
				Finding: support.NewReadinessFinding(
					"readiness.agent_ca",
					title,
					body,
					support.LocalAction{Label: "Agent enrollment and rotation", Href: "/docs/api#agents", Kind: support.ActionNavigate},
				),
			}
		}
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
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	src := s.supportSources(r.Context(), tid)
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
// tenant-scoped anonymized counts, and the known secrets are passed as
// RedactValues so they are scrubbed from the assembled bytes (defense in depth).
func (s *Server) supportSources(ctx context.Context, tenant string) support.Sources {
	return support.Sources{
		Version:          version.Get(),
		ConfigRedacted:   s.cfg.Redacted(),
		Health:           s.deepHealth(ctx),
		SelfMetrics:      support.SelfSnapshot(s.startedAt),
		Topology:         s.topologySummary(ctx, tenant),
		DeviceCollection: s.supportDeviceCollection(ctx, tenant),
		FlowQuality:      s.supportFlowQuality(ctx, tenant),
		Runtime:          support.CollectRuntime(s.startedAt),
		RedactValues:     s.knownSecrets(),
	}
}

func (s *Server) supportFlowQuality(ctx context.Context, tenant string) support.FlowQualitySummary {
	out := support.FlowQualitySummary{
		ContractVersion: flow.QualityContractVersion,
		IngestRunning:   s.flowQuality != nil,
		Receipts:        []support.FlowQualityReceipt{},
	}
	if s.flowQuality == nil || tenant == "" {
		return out
	}
	rows, truncated, err := s.flowQuality.ListQualityReceipts(ctx, tenant, flow.QualityFilter{
		Limit: flow.MaxQualityReceiptRead,
	})
	if err != nil {
		out.Error = "tenant-scoped flow quality read unavailable"
		return out
	}
	agentRefs, exporterRefs := map[string]string{}, map[string]string{}
	for _, row := range rows {
		if agentRefs[row.AgentID] == "" {
			agentRefs[row.AgentID] = fmt.Sprintf("agent-%04d", len(agentRefs)+1)
		}
		exporterKey := row.AgentID + "\x00" + row.ExporterAddress
		if exporterRefs[exporterKey] == "" {
			exporterRefs[exporterKey] = fmt.Sprintf("exporter-%04d", len(exporterRefs)+1)
		}
		out.Receipts = append(out.Receipts, support.FlowQualityReceipt{
			AgentRef: agentRefs[row.AgentID], ExporterRef: exporterRefs[exporterKey],
			Protocol: row.Protocol, State: row.State, Reason: row.Reason,
			PacketsReceived: row.PacketsReceived, RecordsDecoded: row.RecordsDecoded,
			DecodeErrorPackets: row.DecodeErrorPackets, TemplateMisses: row.TemplateMisses,
			QueueDroppedRecords: row.QueueDroppedRecords, EmitDroppedRecords: row.EmitDroppedRecords,
			TemplateState: row.TemplateState, SamplingState: row.SamplingState,
			NextAction: row.NextAction,
		})
	}
	out.Truncated = truncated
	return out
}

func (s *Server) supportDeviceCollection(ctx context.Context, tenant string) support.DeviceCollectionSummary {
	out := support.DeviceCollectionSummary{
		ContractVersion:   "probectl.device-collection-outcomes/v1",
		CollectionRunning: s.deviceOutcomes != nil,
		Receipts:          []support.DeviceCollectionReceipt{},
	}
	if s.deviceOutcomes == nil || tenant == "" {
		return out
	}
	rows, truncated, err := s.deviceOutcomes.ListCollectionOutcomes(ctx, tenant, device.CollectionOutcomeFilter{
		Limit: device.MaxCollectionOutcomeRead,
	})
	if err != nil {
		out.Error = "tenant-scoped outcome read unavailable"
		return out
	}
	agentRefs, targetRefs := map[string]string{}, map[string]string{}
	for _, row := range rows {
		if agentRefs[row.AgentID] == "" {
			agentRefs[row.AgentID] = fmt.Sprintf("agent-%04d", len(agentRefs)+1)
		}
		targetKey := row.AgentID + "\x00" + row.ConfiguredTarget
		if targetRefs[targetKey] == "" {
			targetRefs[targetKey] = fmt.Sprintf("target-%04d", len(targetRefs)+1)
		}
		out.Receipts = append(out.Receipts, support.DeviceCollectionReceipt{
			AgentRef: agentRefs[row.AgentID], TargetRef: targetRefs[targetKey],
			Protocol: row.Protocol, LastAttempt: row.LastAttemptAt, LastSuccess: row.LastSuccessAt,
			State: row.State, Reason: row.Reason, RowCount: row.RowCount, NextAction: row.NextAction,
		})
	}
	out.Truncated = truncated
	return out
}

// topologySummary returns ANONYMIZED counts for the authenticated tenant (no
// identifiers or telemetry). Empty when there is no pool or tenant.
func (s *Server) topologySummary(ctx context.Context, tenant string) support.TopologySummary {
	sum := support.TopologySummary{Region: s.cfg.Region, IsolationModels: map[string]int{}}
	if s.pool == nil || tenant == "" {
		return sum
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	return topologySummaryFromTenant(ctx, sum, func(ctx context.Context, fn func(context.Context, tenancy.Scope) error) error {
		return tenancy.InTenant(ctx, s.pool, fn)
	})
}

type topologySummaryErrorCode string

const (
	topologyErrorTenantTopology topologySummaryErrorCode = "tenant_topology"
	topologyErrorAgentsCount    topologySummaryErrorCode = "agents_count"
	topologyErrorTenantScope    topologySummaryErrorCode = "tenant_scope"
)

func topologySummaryFromTenant(ctx context.Context, sum support.TopologySummary, run func(context.Context, func(context.Context, tenancy.Scope) error) error) support.TopologySummary {
	markPartial := func(code topologySummaryErrorCode) {
		sum.Partial = true
		// Support bundles are downloadable artifacts. Keep only this closed set
		// of operational error classes; dependency errors may contain hosts,
		// schemas, DSNs, or credentials that a known-value scrubber cannot
		// reliably recognize.
		sum.Errors = append(sum.Errors, string(code))
	}
	if err := run(ctx, func(ctx context.Context, scope tenancy.Scope) error {
		var isolationModel string
		if err := scope.Q.QueryRow(ctx,
			`SELECT isolation_model
			   FROM public.probectl_current_tenant_topology()
			  WHERE tenant_id = $1`,
			scope.Tenant.String(),
		).Scan(&isolationModel); err != nil {
			markPartial(topologyErrorTenantTopology)
		} else {
			sum.Tenants = 1
			sum.IsolationModels[isolationModel] = 1
		}
		if err := scope.Q.QueryRow(ctx,
			`SELECT count(*)
			   FROM agents
			  WHERE tenant_id = $1`,
			scope.Tenant.String(),
		).Scan(&sum.Agents); err != nil {
			markPartial(topologyErrorAgentsCount)
		}
		return nil
	}); err != nil {
		markPartial(topologyErrorTenantScope)
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
	cand = append(cand, c.DatabaseCredentialValues()...)
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
	out := cand[:0]
	for _, v := range cand {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// pastIssuingRenewalPoint is true once the issuing intermediate has spent
// issuingRenewalFraction of its own lifetime, so the warning means the same
// thing for a one-year intermediate and a ninety-day one. It deliberately
// mirrors the per-agent rule in agentfleet.go: the same question, one level up
// the chain.
func pastIssuingRenewalPoint(notBefore, notAfter, now time.Time) bool {
	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		return false
	}
	return float64(now.Sub(notBefore)) >= issuingRenewalFraction*float64(lifetime)
}

// A quarter of the lifetime left: 91 days for the shipped one-year
// intermediate, which is time to find the offline root key.
const issuingRenewalFraction = 0.75
