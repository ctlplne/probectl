package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/ai"
	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
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

// buildAnalyzer wires the RCA Analyzer (S24) over the S23 query engine, so RCA is
// grounded in real, RLS-scoped signals. The model defaults to the in-process,
// air-gapped built-in synthesizer.
func buildAnalyzer(cfg *config.Config, log *slog.Logger, pool *pgxpool.Pool) *ai.Analyzer {
	return ai.NewAnalyzer(buildEngine(cfg, pool), ai.WithModel(buildModel(cfg, log)), ai.WithMaxEvidence(cfg.AIMaxEvidence))
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
	})
	if err != nil {
		log.Warn("ai model adapter unavailable; using the built-in air-gapped synthesizer", "error", err)
		return ai.NewBuiltinModel()
	}
	return m
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
		s.log.Warn("ai analyze failed", "error", err)
		return apierror.Unavailable("the AI assistant is temporarily unavailable")
	}
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
