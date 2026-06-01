package control

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/apierror"
	"github.com/imfeelingtheagi/netctl/internal/path"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

// handleGetPath returns the latest discovered path for a test — the path-viz data
// API. It 404s when no discovery has run for the test's target yet.
func (s *Server) handleGetPath(w http.ResponseWriter, r *http.Request) error {
	target, err := s.testTarget(r)
	if err != nil {
		return err
	}
	tid, err := s.resolveTenant(r)
	if err != nil {
		return err
	}
	p, found, err := s.pathStore.Latest(r.Context(), tid.String(), target)
	if err != nil {
		return apierror.Internal("path lookup failed").Wrap(err)
	}
	if !found {
		return apierror.NotFound("no path has been discovered for this test yet")
	}
	writeJSON(w, http.StatusOK, p)
	return nil
}

// handleDiscoverPath runs a path discovery for a test, stores it, and returns it.
func (s *Server) handleDiscoverPath(w http.ResponseWriter, r *http.Request) error {
	target, err := s.testTarget(r)
	if err != nil {
		return err
	}
	tid, err := s.resolveTenant(r)
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
	if err := s.pathStore.Save(r.Context(), tid.String(), p); err != nil {
		return apierror.Internal("path save failed").Wrap(err)
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
