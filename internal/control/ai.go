// SPDX-License-Identifier: LicenseRef-probectl-TBD

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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// buildEngine wires the S23 query engine: the cost guard plus the tenant-scoped
// incident store as the entities source (the cross-plane correlation home, S17).
// Shared by the RCA analyzer (S24) and the MCP backend (S25).
func buildEngine(cfg *config.Config, pool *pgxpool.Pool) *ai.Engine {
	opts := []ai.Option{ai.WithMaxRows(cfg.AIMaxEvidence)}
	if pool != nil {
		opts = append(opts,
			ai.WithEntities(incidentEntitiesSource{pool: pool}),
			// Change events are the "what changed?" evidence the planner routes
			// deploy/config/routing questions to (DomainEvents), so RCA can cite the
			// likely change (S29).
			ai.WithEvents(changeEventsSource{pool: pool}),
		)
	}
	return ai.NewEngine(opts...)
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
	}
}

// buildAnalyzerWithGate wires the RCA Analyzer (S24) over the S23 query engine,
// so RCA is grounded in real, RLS-scoped signals; the server composes ONE
// gate and shares it across the analyzer, MCP, and authoring surfaces.
func buildAnalyzerWithGate(cfg *config.Config, log *slog.Logger, pool *pgxpool.Pool, gate *ai.EgressGate) *ai.Analyzer {
	return ai.NewAnalyzer(buildEngine(cfg, pool),
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

// tenantEgressPolicy reads tenant_governance.ai_remote_egress (default-deny:
// no row, no pool, or any error = no egress).
func tenantEgressPolicy(pool *pgxpool.Pool) ai.EgressPolicy {
	return func(ctx context.Context, tenantID string) (bool, error) {
		if pool == nil {
			return false, nil
		}
		allowed := false
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			row := sc.Q.QueryRow(ctx, `SELECT ai_remote_egress FROM tenant_governance WHERE tenant_id = $1`, tenantID)
			if err := row.Scan(&allowed); err != nil {
				allowed = false // no policy row = no consent
			}
			return nil
		})
		if err != nil {
			return false, nil // fail closed, never fail open
		}
		return allowed, nil
	}
}

// egressAuditor appends ai.remote_egress to the tenant's tamper-evident audit
// stream: endpoint, model, and the DATA CATEGORIES that left (never content).
func egressAuditor(pool *pgxpool.Pool, log *slog.Logger) ai.EgressAudit {
	return func(ctx context.Context, ev ai.EgressEvent) {
		log.Info("ai remote egress", "tenant_id", ev.TenantID, "endpoint", ev.Endpoint,
			"model", ev.Model, "evidence", ev.EvidenceCount, "planes", ev.Planes)
		if pool == nil {
			return
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(ev.TenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := audit.TenantAppend(ctx, sc, "system", "ai.remote_egress", ev.Endpoint, map[string]any{
				"model": ev.Model, "evidence_count": ev.EvidenceCount, "planes": ev.Planes,
			})
			return err
		}); err != nil {
			// CODE-002: never silently drop the egress audit record on a transient
			// fault — surface it (the egress itself already happened).
			log.Warn("failed to persist ai.remote_egress audit record", "tenant_id", ev.TenantID, "error", err.Error())
		}
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
		target, prefix := sel["target"], sel["prefix"]
		for i := range incs {
			if len(rows) >= limit {
				break
			}
			inc := incs[i]
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
	if p := auth.PrincipalFrom(r.Context()); p != nil {
		usage.Record(p.TenantID, usage.MeterAICalls, 1) // metering seam (S-T3)
	}
	q := strings.TrimSpace(req.Question)
	if q == "" || len(q) > 2000 {
		return apierror.Validation("question is required (1–2000 characters)")
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	ans, err := s.analyzer.Analyze(r.Context(), p, ai.Question{Text: q, Subject: req.Subject})
	if err != nil {
		if errors.Is(err, ai.ErrNoTenant) {
			return apierror.Unauthorized("authentication required")
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
			return s.recordAudit(ctx, sc, r, "ai.ask", ans.ID, map[string]any{"question": q})
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
	payload, err := json.Marshal(ans)
	if err != nil {
		s.log.Warn("ai answer marshal failed", "error", err)
		return
	}
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.AIAnswers{}).Save(ctx, sc, store.AIAnswerInput{
			AnswerID: ans.ID, Question: ans.Question, RootCause: ans.RootCause,
			Confidence: string(ans.Confidence), Model: ans.Model,
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
