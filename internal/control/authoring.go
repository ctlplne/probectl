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
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/author"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// buildAuthor wires the AI test-authoring engine (S26). It uses the configured
// model when one is set (reusing the S24 model config) and otherwise the
// deterministic, air-gapped heuristic — so authoring works with zero external
// calls by default.
func buildAuthor(cfg *config.Config, log *slog.Logger, gate *ai.EgressGate) *author.Engine {
	m := buildModel(cfg, log)
	if c, ok := m.(ai.RemoteCompleter); ok {
		// AIRCA-005: the authoring model rides the SAME egress gate as RCA
		// and MCP — per-tenant consent, redaction, audit. A remote authoring
		// call without consent is denied; the heuristic author still works.
		return author.NewEngine(author.NewModelAuthor(ai.NewGatedCompleter(c, gate), m.Name()))
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

const (
	discoverFlowWindow   = time.Hour
	discoverFlowLimit    = 20
	discoverFlowMinCount = 2
)

// handleAIDiscover proposes monitorable targets mined from the tenant's observed
// incidents and top flow destinations. Flow observations are a separately
// permissioned, bounded read: test.write alone must never reveal flow metadata.
// The eBPF service map / BGP / DNS plug into the same Observation input as those
// sources are wired. Results are ranked, thresholded, deduped, schema-validated,
// and returned as proposals only.
// maxInt is the largest value an int holds on this platform, used to saturate
// a uint64 row count instead of letting the conversion wrap (DPR-246).
const maxInt = uint64(^uint(0) >> 1)

func (s *Server) handleAIDiscover(w http.ResponseWriter, r *http.Request) error {
	principal := auth.PrincipalFrom(r.Context())
	if principal == nil {
		return apierror.Unauthorized("authentication required")
	}
	tenantID := strings.TrimSpace(principal.TenantID)
	if tenantID == "" {
		return apierror.Unauthorized("tenant identity required")
	}
	var obs []author.Observation
	var existing []string
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			tests, e := store.Tests{}.ListAll(ctx, sc, 0)
			if e != nil {
				return e
			}
			for _, t := range tests {
				existing = append(existing, t.Target)
			}
			incs, _, e := store.Incidents{}.List(ctx, sc, store.DefaultIncidentListLimit)
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
	// Flow destinations are tenant-owned telemetry. Require the source-specific
	// RBAC grant AND its ABAC deny-override even though the route's outer
	// permission is test.write. A caller without flow.read can still receive
	// incident-derived proposals, but learns nothing from the flow plane.
	if reason, err := s.decide(r.Context(), principal, permFlowRead, auth.RBACGlobal, nil); err != nil {
		return err
	} else if reason == auth.DecisionAllowed {
		{
			rows, err := s.flowStore.TopTalkers(r.Context(), flowstore.TopQuery{
				TenantID: tenantID,
				By:       flowstore.ByDst,
				Window:   discoverFlowWindow,
				Limit:    discoverFlowLimit,
			})
			if err != nil {
				return apierror.Unavailable("flow-derived discovery is temporarily unavailable").Wrap(err)
			}
			for _, row := range rows {
				if row.Flows < discoverFlowMinCount {
					continue
				}
				// DPR-246: bound BEFORE converting, not after. The old code did
				// count := int(row.Flows) and then corrected it, so on a value above
				// MaxInt the conversion had already wrapped negative and the
				// correctness depended on the follow-up check rather than on the
				// conversion being safe.
				count := int(maxInt)
				if row.Flows <= maxInt {
					count = int(row.Flows)
				}
				obs = append(obs, author.Observation{
					Target: row.Key,
					Kind:   "flow",
					Count:  count,
				})
			}
		}
	}
	// Incident targets are already correlated signals (low noise), so a single
	// occurrence is worth proposing. Flow observations were separately filtered
	// to at least discoverFlowMinCount above.
	proposals := author.Discover(obs, existing, author.DiscoverOptions{MinCount: 1})
	writeJSON(w, http.StatusOK, map[string]any{"proposals": proposals})
	return nil
}
