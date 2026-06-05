package control

import (
	"errors"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
)

// The tenant fairness self-view (S-T7, core): a tenant can always see the
// bounds it runs under and what was admitted/shed/rejected — debugging a
// fairness dispute must not require the provider's word for it. Enforcement
// is core (it protects the pooled platform); the cross-tenant views are the
// provider console's (ee/).

// WithFairness attaches the process-wide fairness gate. nil = no enforcement
// and the self-view reports enforcement off.
func (s *Server) WithFairness(g *fairness.Gate) *Server {
	if g != nil {
		s.fairnessGate = g
	}
	return s
}

func (s *Server) handleFairnessSelf(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.fairnessGate == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enforcing": false})
		return nil
	}
	snap := s.fairnessGate.SnapshotTenant(r.Context(), tid)
	writeJSON(w, http.StatusOK, map[string]any{
		"enforcing": true,
		"policy":    snap.Policy,
		"ingest":    snap.Ingest,
		"queries":   snap.Queries,
	})
	return nil
}

// beginQuery admits one query under the caller's per-tenant query-cost
// guards (S-T7, extending the S23 deployment-wide guards). The returned
// release is never nil. Rejections are 429 with Retry-After — an over-budget
// tenant gets a clear signal, never a slow platform.
func (s *Server) beginQuery(w http.ResponseWriter, r *http.Request) (func(), error) {
	if s.fairnessGate == nil {
		return func() {}, nil
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return func() {}, nil // unauthenticated paths fail later on auth, not fairness
	}
	release, err := s.fairnessGate.BeginQuery(r.Context(), tid)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		switch {
		case errors.Is(err, fairness.ErrQueryConcurrency):
			return nil, apierror.RateLimited("tenant query concurrency limit reached — retry shortly")
		case errors.Is(err, fairness.ErrQueryBudget):
			return nil, apierror.RateLimited("tenant query budget exhausted — retry shortly")
		}
		return nil, apierror.RateLimited(err.Error())
	}
	return release, nil
}
