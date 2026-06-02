package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/netctl/internal/ai/author"
	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/auth"
	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

// buildAuthor wires the AI test-authoring engine (S26). It uses the configured
// model when one is set (reusing the S24 model config) and otherwise the
// deterministic, air-gapped heuristic — so authoring works with zero external
// calls by default.
func buildAuthor(cfg *config.Config, log *slog.Logger) *author.Engine {
	m := buildModel(cfg, log)
	if c, ok := m.(author.Completer); ok {
		return author.NewEngine(author.NewModelAuthor(c, m.Name()))
	}
	return author.NewEngine(author.HeuristicAuthor{})
}

// --- /v1/ai/author + /v1/ai/discover handlers (propose only — never auto-apply) ---

type authorRequest struct {
	Prompt string `json:"prompt"`
}

// handleAIAuthor turns a natural-language request into a schema-valid test config
// pending the user's confirmation. It NEVER creates the test (CLAUDE.md §7
// guardrail 8 — propose, human-gated); the user applies it via POST /v1/tests.
func (s *Server) handleAIAuthor(w http.ResponseWriter, r *http.Request) error {
	var req authorRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	prompt := strings.TrimSpace(req.Prompt)
	if prompt == "" || len(prompt) > 2000 {
		return apierror.Validation("prompt is required (1–2000 characters)")
	}
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		return apierror.Unauthorized("authentication required")
	}
	proposal, err := s.authorEngine.Author(r.Context(), prompt)
	if err != nil {
		if errors.Is(err, author.ErrModelUnavailable) {
			s.log.Warn("ai author model unavailable", "error", err)
			return apierror.Unavailable("the authoring model is temporarily unavailable")
		}
		// ErrCannotAuthor (or an invalid generated config) → a 422 with guidance.
		return apierror.Validation(err.Error())
	}
	if s.pool != nil {
		if auditErr := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "ai.author", "", map[string]any{"type": proposal.Spec.Type, "target": proposal.Spec.Target})
		}); auditErr != nil {
			s.log.Warn("audit ai.author failed", "error", auditErr)
		}
	}
	writeJSON(w, http.StatusOK, proposal)
	return nil
}

// handleAIDiscover proposes monitorable targets mined from the tenant's observed
// telemetry (incident targets today; the eBPF service map / flows / BGP / DNS plug
// into the same Observation input as those sources are wired), ranked, thresholded
// to avoid noise, and deduped against existing tests. Proposals only.
func (s *Server) handleAIDiscover(w http.ResponseWriter, r *http.Request) error {
	if auth.PrincipalFrom(r.Context()) == nil {
		return apierror.Unauthorized("authentication required")
	}
	var obs []author.Observation
	var existing []string
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			tests, e := store.Tests{}.List(ctx, sc)
			if e != nil {
				return e
			}
			for _, t := range tests {
				existing = append(existing, t.Target)
			}
			incs, e := store.Incidents{}.List(ctx, sc)
			if e != nil {
				return e
			}
			counts := map[string]int{}
			for _, inc := range incs {
				target := inc.Target
				if target == "" {
					target = inc.Prefix
				}
				if target != "" {
					counts[target]++
				}
			}
			for target, n := range counts {
				obs = append(obs, author.Observation{Target: target, Kind: "incident", Count: n})
			}
			return nil
		}); err != nil {
			return err
		}
	}
	// Incident targets are already correlated signals (low noise), so a single
	// occurrence is worth proposing.
	proposals := author.Discover(obs, existing, author.DiscoverOptions{MinCount: 1})
	writeJSON(w, http.StatusOK, map[string]any{"proposals": proposals})
	return nil
}
