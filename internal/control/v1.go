package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

// apiRoute binds a method+pattern to a handler. This table is the single source
// of truth for routing AND the OpenAPI-matches-handlers check (no undocumented
// routes — CLAUDE.md §6, §8).
type apiRoute struct {
	Method  string
	Pattern string
	Handler apiHandler
}

func (s *Server) apiRoutes() []apiRoute {
	return []apiRoute{
		{http.MethodGet, "/v1/tests", s.handleListTests},
		{http.MethodPost, "/v1/tests", s.handleCreateTest},
		{http.MethodGet, "/v1/tests/{id}", s.handleGetTest},
		{http.MethodPut, "/v1/tests/{id}", s.handleUpdateTest},
		{http.MethodDelete, "/v1/tests/{id}", s.handleDeleteTest},
		{http.MethodGet, "/v1/tests/{id}/path", s.handleGetPath},
		{http.MethodPost, "/v1/tests/{id}/path", s.handleDiscoverPath},
		{http.MethodGet, "/v1/agents", s.handleListAgents},
		{http.MethodGet, "/v1/agents/{id}", s.handleGetAgent},
		{http.MethodPatch, "/v1/agents/{id}", s.handlePatchAgent},
		{http.MethodDelete, "/v1/agents/{id}", s.handleDeleteAgent},
	}
}

// inTenant resolves the caller's tenant (stub auth → default) and runs fn inside
// a tenant-scoped, RLS-enforced transaction.
func (s *Server) inTenant(r *http.Request, fn func(context.Context, tenancy.Scope) error) error {
	tid, err := s.resolveTenant(r)
	if err != nil {
		return err
	}
	return tenancy.InTenant(tenancy.WithTenant(r.Context(), tid), s.pool, fn)
}

// --- tests ---

var validTestTypes = map[string]bool{
	"icmp": true, "tcp": true, "udp": true, "noop": true,
	"dns": true, "http": true, "a2a": true,
}

type testRequest struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params"`
	Enabled         *bool             `json:"enabled"`
}

func (req testRequest) toInput() (store.TestInput, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		return store.TestInput{}, apierror.Validation("name is required (1–200 characters)")
	}
	if !validTestTypes[req.Type] {
		return store.TestInput{}, apierror.Validation("type must be one of icmp, tcp, udp, dns, http, a2a, noop")
	}
	target := strings.TrimSpace(req.Target)
	if req.Type != "noop" && target == "" {
		return store.TestInput{}, apierror.Validation("target is required")
	}
	interval := req.IntervalSeconds
	if interval == 0 {
		interval = 60
	}
	if interval < 1 || interval > 86400 {
		return store.TestInput{}, apierror.Validation("interval_seconds must be between 1 and 86400")
	}
	timeout := req.TimeoutSeconds
	if timeout == 0 {
		timeout = 3
	}
	if timeout < 1 || timeout > 300 {
		return store.TestInput{}, apierror.Validation("timeout_seconds must be between 1 and 300")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return store.TestInput{
		Name: name, Type: req.Type, Target: target,
		IntervalSeconds: interval, TimeoutSeconds: timeout,
		Params: req.Params, Enabled: enabled,
	}, nil
}

func (s *Server) handleListTests(w http.ResponseWriter, r *http.Request) error {
	var tests []store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.List(ctx, sc)
		tests = t
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tests})
	return nil
}

func (s *Server) handleCreateTest(w http.ResponseWriter, r *http.Request) error {
	var req testRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	in, err := req.toInput()
	if err != nil {
		return err
	}
	var created *store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.Create(ctx, sc, in)
		created = t
		return e
	}); err != nil {
		return err
	}
	w.Header().Set("Location", "/v1/tests/"+created.ID)
	writeJSON(w, http.StatusCreated, created)
	return nil
}

func (s *Server) handleGetTest(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var t *store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Tests{}.Get(ctx, sc, id)
		t = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

func (s *Server) handleUpdateTest(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var req testRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	in, err := req.toInput()
	if err != nil {
		return err
	}
	var t *store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Tests{}.Update(ctx, sc, id, in)
		t = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, t)
	return nil
}

func (s *Server) handleDeleteTest(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return store.Tests{}.Delete(ctx, sc, id)
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// --- agents (registered via mTLS; the API manages their labels + lifecycle) ---

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) error {
	var agents []store.Agent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		a, e := store.Agents{}.List(ctx, sc)
		agents = a
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": agents})
	return nil
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var a *store.Agent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Agents{}.Get(ctx, sc, id)
		a = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, a)
	return nil
}

type agentPatch struct {
	Name string `json:"name"`
}

func (s *Server) handlePatchAgent(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var req agentPatch
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		return apierror.Validation("name is required (1–200 characters)")
	}
	var a *store.Agent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Agents{}.Rename(ctx, sc, id, name)
		a = x
		return e
	}); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, a)
	return nil
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		return store.Agents{}.Delete(ctx, sc, id)
	}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// decodeJSON decodes a size-limited JSON request body, mapping malformed input
// to a 400.
func decodeJSON(r *http.Request, dst any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(dst); err != nil {
		return apierror.BadRequest("invalid JSON request body")
	}
	return nil
}
