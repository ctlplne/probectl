// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

var pathRoundIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// WithHopGeo attaches the operator-supplied hop location table (see
// internal/path/geo.go). nil is a no-op: hops simply stay unlocated and the
// UI's geography view says so honestly. Returns the server for chaining.
func (s *Server) WithHopGeo(table *path.GeoTable) *Server {
	if table != nil {
		s.hopGeo = table
	}
	return s
}

// handleGetPath returns the latest discovered path for a test — the path-viz data
// API. It 404s when no discovery has run for the test's target yet.
func (s *Server) handleGetPath(w http.ResponseWriter, r *http.Request) error {
	target, err := s.testTarget(r)
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	p, found, err := s.pathStore.Latest(r.Context(), tid, target)
	if err != nil {
		return apierror.Internal("path lookup failed").Wrap(err)
	}
	if !found {
		return apierror.NotFound("no path has been discovered for this test yet")
	}
	s.hopGeo.Enrich(p)
	writeJSON(w, http.StatusOK, p)
	return nil
}

// handleGetPathHistory returns immutable discovery rounds for one test. The
// test lookup resolves the tenant-owned target first; the path store then
// constrains every metadata/hop/link query by tenant_id + target. round_id is
// an opaque selector for stable links, never an authorization boundary.
func (s *Server) handleGetPathHistory(w http.ResponseWriter, r *http.Request) error {
	target, err := s.testTarget(r)
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	query, err := parsePathHistoryQuery(r)
	if err != nil {
		return err
	}
	rounds, err := s.pathStore.History(r.Context(), tid, target, query)
	if err != nil {
		return apierror.Internal("path history lookup failed").Wrap(err)
	}
	for i := range rounds {
		s.hopGeo.Enrich(&rounds[i].Path)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rounds})
	return nil
}

func parsePathHistoryQuery(r *http.Request) (pathstore.HistoryQuery, error) {
	var out pathstore.HistoryQuery
	parseTime := func(name string) (time.Time, error) {
		raw := r.URL.Query().Get(name)
		if raw == "" {
			return time.Time{}, nil
		}
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, apierror.Validation(name + " must be an RFC3339 timestamp")
		}
		return parsed.UTC(), nil
	}
	var err error
	if out.From, err = parseTime("from"); err != nil {
		return out, err
	}
	if out.To, err = parseTime("to"); err != nil {
		return out, err
	}
	if !out.From.IsZero() && !out.To.IsZero() && out.From.After(out.To) {
		return out, apierror.Validation("from must be at or before to")
	}
	out.Limit = 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return out, apierror.Validation("limit must be between 1 and 100")
		}
		out.Limit = limit
	}
	ids := r.URL.Query()["round_id"]
	if len(ids) > 2 {
		return out, apierror.Validation("at most two round_id values are allowed")
	}
	for _, id := range ids {
		if !pathRoundIDRE.MatchString(id) {
			return out, apierror.Validation("round_id is malformed")
		}
		out.IDs = append(out.IDs, id)
	}
	return out, nil
}

// handleDiscoverPath runs a path discovery for a test, stores it, and returns it.
func (s *Server) handleDiscoverPath(w http.ResponseWriter, r *http.Request) error {
	target, err := s.testTarget(r)
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}

	cfg := path.Config{Target: target, Mode: "icmp", MaxHops: 30, TraceCount: 3, PerHopTimeout: 2 * time.Second}
	dctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	p, err := s.discover(dctx, cfg)
	if err != nil {
		return apierror.Internal("path discovery failed").Wrap(err)
	}
	if err := s.pathStore.Save(r.Context(), tid, p); err != nil {
		return apierror.Internal("path save failed").Wrap(err)
	}
	// Fold the discovery into the dependency graph (S43): the path plane
	// feeds topology at save time — no second discovery pass.
	if s.topo != nil {
		graph, err := s.topo.ForTenant(tid)
		if err != nil {
			return apierror.Forbidden("tenant topology scope is invalid").Wrap(err)
		}
		graph.ObservePath(topology.FromPath(*p, "control"), time.Now())
	}
	writeJSON(w, http.StatusOK, p)
	return nil
}

// testTarget resolves the path target (the host) of the test named in the route.
func (s *Server) testTarget(r *http.Request) (string, error) {
	id := r.PathValue("id")
	var target string
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.Get(ctx, sc, id)
		if e != nil {
			return e
		}
		target = pathHost(t.Target)
		return nil
	}); err != nil {
		return "", err
	}
	return target, nil
}

// pathHost strips a port from a target — path discovery traces to the host.
func pathHost(target string) string {
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}
