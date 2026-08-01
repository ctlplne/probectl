// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
	"github.com/ctlplne/probectl/internal/usage"
)

// AISources are the production telemetry stores that can contribute direct RCA
// evidence. They are optional because small deployments may run without a TSDB,
// flow store, or topology engine; missing sources degrade to "no evidence from
// that plane" rather than widening or failing the query.
type AISources struct {
	Metrics   tsdb.Writer
	Flow      flowstore.Store
	Topology  topology.Store
	DeviceOps device.OpsStore
}

func firstAISources(sources []AISources) AISources {
	if len(sources) == 0 {
		return AISources{}
	}
	return sources[0]
}

// buildEngineWithPolicyLoader wires the policy store into every secondary
// telemetry permission checked inside composite AI reads. The outer HTTP/MCP
// permission is not enough: each metrics/events/entities/topology source gets
// its own tenant-first RBAC+ABAC decision immediately before dispatch.
func buildEngineWithPolicyLoader(
	cfg *config.Config,
	pool *pgxpool.Pool,
	policyLoader func(context.Context, string) ([]auth.Policy, error),
	sources ...AISources,
) *ai.Engine {
	src := firstAISources(sources)
	opts := []ai.Option{ai.WithMaxRows(cfg.AIMaxEvidence)}
	if policyLoader != nil {
		opts = append(opts, ai.WithPermissionAuthorizer(
			func(ctx context.Context, principal *auth.Principal, permission string) (bool, error) {
				policies, err := policyLoader(ctx, principal.TenantID)
				if err != nil {
					return false, err
				}
				resource := map[string]string{auth.ResourceTenantKey: principal.TenantID}
				return auth.Authorize(principal, permission, policies, resource), nil
			},
		))
	}
	if src.Metrics != nil {
		opts = append(opts, ai.WithMetrics(metricsEvidenceSource{writer: src.Metrics}))
	}
	if src.Topology != nil {
		opts = append(opts, ai.WithTopology(ai.NewTopologySource(src.Topology)))
	}
	if pool != nil {
		opts = append(opts,
			ai.WithEntities(incidentEntitiesSource{pool: pool}),
		)
	}
	if pool != nil || src.Flow != nil || src.DeviceOps != nil {
		// The events domain is the high-cardinality event drawer: change
		// timeline rows plus flow summaries when a flow store is attached.
		opts = append(opts, ai.WithEvents(changeEventsSource{pool: pool, flow: src.Flow, configs: src.DeviceOps}))
	}
	return ai.NewEngine(opts...)
}

func (s *Server) aiSources() AISources {
	return AISources{Metrics: s.tsdbWriter, Flow: s.flowStore, Topology: s.topo, DeviceOps: s.deviceOps}
}

func (s *Server) rebuildAnalyzer() {
	if s.egressGate == nil {
		return
	}
	s.analyzer = buildAnalyzerWithPolicyLoader(
		s.cfg, s.log, s.pool, s.egressGate, s.aiPolicyLoader(), s.aiSources())
}

func (s *Server) aiPolicyLoader() func(context.Context, string) ([]auth.Policy, error) {
	if s == nil || s.abac == nil {
		return nil
	}
	return s.abac.policies
}

// NewAIEgressGate constructs THE external-AI egress gate (AIRCA-001/005):
// one instance per server, one consent source, one redaction policy, one
// audit sink — the RCA analyzer, the MCP server, and the test-authoring
// model all draw from it. Standalone MCP uses the same factory because it runs
// without the API server instance.
func NewAIEgressGate(cfg *config.Config, log *slog.Logger, pool *pgxpool.Pool) *ai.EgressGate {
	return ai.NewEgressGate(tenantEgressPolicy(pool), egressAuditor(pool, log), redactionPolicy(cfg))
}

// AIEgressGate exposes the already-built server gate for companion surfaces
// started by main, such as MCP/HTTP. The pointer identity matters: consent,
// redaction, and audit should not drift by surface.
func (s *Server) AIEgressGate() *ai.EgressGate { return s.egressGate }

// redactionPolicy maps the config knobs onto the C8 redaction policy
// (custom patterns were compile-checked at config load — fail closed there).
func redactionPolicy(cfg *config.Config) ai.RedactionPolicy {
	custom, _ := ai.CompileCustomPatterns(cfg.AIRedactCustom)
	return ai.RedactionPolicy{
		MaskIPs:        cfg.AIRedactIPs,
		MaskHostnames:  cfg.AIRedactHostnames,
		MaskPII:        cfg.AIRedactPII,
		CustomPatterns: custom,
		TokenKey:       append([]byte(nil), cfg.SessionHMACKey...),
	}
}

// buildAnalyzerWithPolicyLoader wires RCA over the tenant-scoped query engine
// and the same ABAC cache used by the calling API or MCP surface.
func buildAnalyzerWithPolicyLoader(
	cfg *config.Config,
	log *slog.Logger,
	pool *pgxpool.Pool,
	gate *ai.EgressGate,
	policyLoader func(context.Context, string) ([]auth.Policy, error),
	sources ...AISources,
) *ai.Analyzer {
	return ai.NewAnalyzer(buildEngineWithPolicyLoader(cfg, pool, policyLoader, sources...),
		ai.WithModel(buildModel(cfg, log)),
		ai.WithMaxEvidence(cfg.AIMaxEvidence),
		// U-048: process-wide concurrency backstop (fail-fast 429), effective
		// even when no fairness gate is configured.
		ai.WithMaxConcurrent(cfg.AIMaxConcurrent),
		// U-013 + AIRCA-001: remote-model consent + audit come from the ONE
		// shared egress gate. Local/builtin paths skip both.
		ai.WithEgressGate(gate),
	)
}

var errTenantEgressPolicyUnavailable = errors.New("tenant AI egress policy store unavailable")

// tenantEgressPolicy reads tenant_governance.ai_remote_egress. No row is a
// normal consent_missing decision; a missing store or query/transaction fault
// remains an error so the shared gate can durably classify it as policy_error.
// Both paths fail closed, but their bounded audit reasons stay truthful.
func tenantEgressPolicy(pool *pgxpool.Pool) ai.EgressPolicy {
	return func(ctx context.Context, tenantID string) (bool, error) {
		if pool == nil {
			return false, errTenantEgressPolicyUnavailable
		}
		allowed := false
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			row := sc.Q.QueryRow(ctx, `SELECT ai_remote_egress FROM tenant_governance WHERE tenant_id = $1`, tenantID)
			return row.Scan(&allowed)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil // no policy row = no consent
		}
		if err != nil {
			return false, fmt.Errorf("read tenant AI egress policy: %w", err)
		}
		return allowed, nil
	}
}

// egressAuditor appends ai.remote_egress to the tenant's tamper-evident audit
// stream: endpoint, model, and the DATA CATEGORIES that left (never content).
func egressAuditor(pool *pgxpool.Pool, log *slog.Logger) ai.EgressAudit {
	return func(ctx context.Context, ev ai.EgressEvent) error {
		// Treat adapter-provided provenance as untrusted even though the shared
		// gate already sanitizes it. This is the final log/audit sink.
		ev.Endpoint = ai.SanitizeEndpointProvenance(ev.Endpoint)
		action := "ai.remote_egress"
		message := "ai remote egress"
		if ev.Denied {
			action = "ai.remote_egress_denied"
			message = "ai remote egress denied"
		}
		log.Info(message, "tenant_id", ev.TenantID, "endpoint", ev.Endpoint,
			"model", ev.Model, "surface", ev.Surface, "evidence", ev.EvidenceCount,
			"planes", ev.Planes, "denied", ev.Denied, "denial_reason", ev.DenialReason)
		if pool == nil {
			log.Warn("failed to persist ai.remote_egress audit record", "tenant_id", ev.TenantID, "error", "audit store unavailable")
			return ai.ErrEgressAuditUnavailable
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(ev.TenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := audit.TenantAppend(ctx, sc, "system", action, ev.Endpoint, aiRemoteEgressAuditData(ev))
			return err
		}); err != nil {
			// CODE-002: never silently drop the egress audit record on a transient
			// fault. The caller refuses the external dispatch/output.
			log.Warn("failed to persist ai.remote_egress audit record", "tenant_id", ev.TenantID, "error", err.Error())
			return ai.ErrEgressAuditUnavailable
		}
		return nil
	}
}

func aiRemoteEgressAuditData(ev ai.EgressEvent) map[string]any {
	return map[string]any{
		"model":          ev.Model,
		"surface":        ev.Surface,
		"evidence_count": ev.EvidenceCount,
		"planes":         ev.Planes,
		"allowed":        !ev.Denied,
		"denial_reason":  ev.DenialReason,
	}
}

// buildModel selects the synthesis backend from config. Default (and fallback on
// a misconfigured endpoint) is the built-in air-gapped synthesizer, so the server
// always starts and RCA always works with zero external calls (guardrail 2).
func buildModel(cfg *config.Config, log *slog.Logger) ai.ModelAdapter {
	if !cfg.AIModelEnabled() {
		return ai.NewBuiltinModel()
	}
	kind := map[string]ai.ModelKind{
		"ollama": ai.KindOllama, "openai": ai.KindOpenAI, "anthropic": ai.KindAnthropic,
	}[cfg.AIModelProvider]
	m, err := ai.NewHTTPModel(ai.HTTPModelConfig{
		Kind:     kind,
		Endpoint: cfg.AIModelEndpoint,
		Model:    cfg.AIModelName,
		Token:    cfg.AIModelToken,
		Timeout:  cfg.AIModelTimeout,
		Redaction: func() *ai.RedactionPolicy { // C8: pre-egress masking knobs
			p := redactionPolicy(cfg)
			return &p
		}(),
	})
	if err != nil {
		log.Warn("ai model adapter unavailable; using the built-in air-gapped synthesizer", "error", err)
		return ai.NewBuiltinModel()
	}
	// AIRCA-004: the configured-model path rides breaker + timeout + response
	// cache and degrades to the air-gapped builtin (clearly marked) when the
	// provider is slow or down. The builtin default above needs none of it.
	return ai.NewResilientModel(m, ai.NewBuiltinModel(), cfg.AIModelTimeout)
}

// incidentEntitiesSource is an ai.EntitiesSource backed by the incident store. It
// opens a tenant-scoped (RLS) transaction for the principal's tenant — passed by
// the engine, never taken from the query — so it can never return another
// tenant's incidents. Each incident contributes itself (a correlated anchor) plus
// its cross-plane signals, individually citable.
type incidentEntitiesSource struct{ pool *pgxpool.Pool }

func (s incidentEntitiesSource) QueryEntities(ctx context.Context, tenant string, sel map[string]string, limit int) ([]ai.Row, error) {
	var rows []ai.Row
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		incs, err := (store.Incidents{}).List(ctx, sc)
		if err != nil {
			return err
		}
		target, prefix, incidentID := sel["target"], sel["prefix"], sel["incident_id"]
		for i := range incs {
			if len(rows) >= limit {
				break
			}
			inc := incs[i]
			if incidentID != "" && inc.ID != incidentID {
				continue
			}
			if !incidentMatches(inc, target, prefix) {
				continue
			}
			rows = append(rows, ai.Row{
				"id": inc.ID, "kind": "incident", "plane": "incident",
				"severity": string(inc.Severity), "title": inc.Title,
				"target": inc.Target, "prefix": inc.Prefix, "occurred_at": inc.LastSeenAt,
			})
			full, err := (store.Incidents{}).Get(ctx, sc, inc.ID)
			if err != nil || full == nil {
				continue
			}
			for j, sig := range full.Signals {
				if len(rows) >= limit {
					break
				}
				rows = append(rows, ai.Row{
					"id": inc.ID + ":" + strconv.Itoa(j), "kind": sig.Kind, "plane": sig.Plane,
					"severity": string(sig.Severity), "title": sig.Title, "summary": sig.Summary,
					"occurred_at": sig.OccurredAt,
				})
			}
		}
		return nil
	})
	return rows, err
}

// incidentMatches keeps an incident as evidence when it concerns the question's
// subject (or when there is no subject — then recent incidents are all relevant).
func incidentMatches(inc incident.Incident, target, prefix string) bool {
	if target == "" && prefix == "" {
		return true
	}
	if prefix != "" && inc.Prefix == prefix {
		return true
	}
	if target != "" && (inc.Target == target || strings.Contains(inc.Title, target) || strings.Contains(inc.Target, target)) {
		return true
	}
	return false
}

// --- /v1/ai handlers ---

type askRequest struct {
	Question string            `json:"question"`
	Subject  map[string]string `json:"subject,omitempty"`
	Range    *struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"range,omitempty"`
}

// handleAIAsk answers a natural-language question with a cited, RBAC-scoped root
// cause. The tenant boundary + per-domain RBAC are enforced inside the analyzer
// (the S23 engine), never by the model.
func (s *Server) handleAIAsk(w http.ResponseWriter, r *http.Request) error {
	// Fairness (S-T7): the per-tenant query-cost guard wraps the whole
	// analysis (it extends the S23 deployment-wide row/timeout guards).
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()
	var req askRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil || p.TenantID == "" {
		return apierror.Unauthorized("authentication required")
	}
	usage.Record(p.TenantID, usage.MeterAICalls, 1) // metering seam (S-T3)
	q := strings.TrimSpace(req.Question)
	if q == "" || len(q) > 2000 {
		return apierror.Validation("question is required (1–2000 characters)")
	}
	for key := range req.Subject {
		normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		if normalized == "tenant" || normalized == "tenant_id" || normalized == "evidence_id" {
			return apierror.Validation("subject may not select tenant or evidence scope; scope comes from authentication")
		}
	}
	var queryRange ai.TimeRange
	if req.Range != nil {
		if req.Range.Start.IsZero() || req.Range.End.IsZero() || req.Range.Start.After(req.Range.End) {
			return apierror.Validation("range requires start <= end as RFC 3339 timestamps")
		}
		queryRange = ai.TimeRange{Start: req.Range.Start, End: req.Range.End}
	}
	ans, err := s.analyzer.Analyze(r.Context(), p, ai.Question{Text: q, Subject: req.Subject, Range: queryRange})
	if err != nil {
		if errors.Is(err, ai.ErrNoTenant) {
			return apierror.Unauthorized("authentication required")
		}
		if errors.Is(err, ai.ErrEgressDenied) {
			return apierror.Forbidden("remote AI model egress is disabled for this tenant; enable tenant_governance.ai_remote_egress or use the air-gapped builtin/local model")
		}
		// U-048: the analyzer's process-wide concurrency backstop is
		// saturated — tell the caller to back off, like the fairness gate.
		if errors.Is(err, ai.ErrBusy) {
			w.Header().Set("Retry-After", "1")
			return apierror.RateLimited("the AI assistant is at capacity — retry shortly")
		}
		s.log.Warn("ai analyze failed", "error", err)
		return apierror.Unavailable("the AI assistant is temporarily unavailable")
	}
	// U-093: optionally persist the artifact (full answer + model/config hash)
	// for reproducibility/disputes; best-effort, never blocks the answer.
	s.persistAnswer(r, ans)
	// RCA is a data-access action — audit it (guardrail 7); a best-effort write
	// that never blocks the answer.
	if s.pool != nil {
		if auditErr := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "ai.ask", ans.ID, s.aiAskAuditData(q, p))
		}); auditErr != nil {
			s.log.Warn("audit ai.ask failed", "error", auditErr)
		}
	}
	writeJSON(w, http.StatusOK, ans)
	return nil
}

// persistAnswer stores the RCA artifact when answer persistence is enabled
// (U-093): the full cited answer JSON plus the model and AI-config hash, then
// opportunistically prunes this tenant's artifacts past retention. Best-effort:
// failures are logged, the answer is already on its way to the caller.
func (s *Server) persistAnswer(r *http.Request, ans ai.Answer) {
	if !s.cfg.AIPersistAnswers || s.pool == nil {
		return
	}
	persisted := s.aiAnswerForPersistence(r, ans)
	payload, err := json.Marshal(persisted)
	if err != nil {
		s.log.Warn("ai answer marshal failed", "error", err)
		return
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.AIAnswers{}).Save(ctx, sc, store.AIAnswerInput{
			AnswerID: ans.ID, Question: persisted.Question, RootCause: persisted.RootCause,
			Confidence: string(persisted.Confidence), Model: persisted.Model,
			ConfigHash: aiConfigHash(s.cfg), Payload: payload,
		}); err != nil {
			return err
		}
		_, err := (store.AIAnswers{}).PruneOlderThan(ctx, sc, s.cfg.AIAnswerRetention)
		return err
	}); err != nil {
		s.log.Warn("ai answer persistence failed", "error", err)
	}
}

func (s *Server) aiAskAuditData(question string, p *auth.Principal) map[string]any {
	tenantID := ""
	if p != nil {
		tenantID = p.TenantID
	}
	return map[string]any{
		"question":          ai.RedactTextForTenant(question, redactionPolicy(s.cfg), tenantID),
		"question_redacted": true,
	}
}

func (s *Server) aiAnswerForPersistence(r *http.Request, ans ai.Answer) ai.Answer {
	tenantID := ans.Tenant
	if tenantID == "" {
		if p := auth.PrincipalFrom(r.Context()); p != nil {
			tenantID = p.TenantID
		}
	}
	return ai.RedactAnswerForPersistence(ans, redactionPolicy(s.cfg), tenantID)
}

// aiConfigHash fingerprints the AI configuration that produced an answer
// (U-093): same hash = same provider/endpoint/model/evidence-cap/redaction, so
// a dispute can establish what setup answered. Never includes the token.
func aiConfigHash(cfg *config.Config) string {
	canon := fmt.Sprintf("provider=%s|endpoint=%s|model=%s|max_evidence=%d|redact_ips=%t|redact_hostnames=%t|redact_pii=%t|redact_custom=%s",
		cfg.AIModelProvider, cfg.AIModelEndpoint, cfg.AIModelName,
		cfg.AIMaxEvidence, cfg.AIRedactIPs, cfg.AIRedactHostnames, cfg.AIRedactPII, cfg.AIRedactCustom)
	return hex.EncodeToString(crypto.Hash([]byte(canon)))
}

type feedbackRequest struct {
	AnswerID string `json:"answer_id"`
	Rating   string `json:"rating"`
	Comment  string `json:"comment,omitempty"`
	Question string `json:"question,omitempty"`
}

// handleAIFeedback records a thumbs up/down on an answer (the answer-quality
// loop), tenant-scoped and audited.
func (s *Server) handleAIFeedback(w http.ResponseWriter, r *http.Request) error {
	var req feedbackRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	fb := ai.Feedback{
		TenantID: p.TenantID, AnswerID: req.AnswerID, Question: req.Question,
		Rating: ai.Rating(req.Rating), Comment: req.Comment, UserID: p.UserID,
	}
	if err := fb.Validate(); err != nil {
		return apierror.Validation("feedback requires answer_id and rating (up|down); comment must be <= 2000 chars")
	}
	if s.pool == nil {
		return apierror.Unavailable("feedback persistence is unavailable")
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.AIFeedback{}).Save(ctx, sc, store.AIFeedbackInput{
			AnswerID: fb.AnswerID, Question: fb.Question, Rating: string(fb.Rating), Comment: fb.Comment, UserID: fb.UserID,
		}); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "ai.feedback", fb.AnswerID, map[string]any{"rating": string(fb.Rating)})
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
