// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CMDB correlation endpoints (S40, F30). The CMDB is deployment-level
// infrastructure, but every request is tenant-scoped FIRST: keys are resolved
// from the caller's own tenant's incidents/agents (or an explicit lookup the
// caller is RBAC'd for), then handed to the read-only resolver.

// BuildCMDB constructs the CMDB resolver from config, or nil when no provider
// is configured (the feature stays off). Secrets come from the environment via
// config — they are never logged.
func BuildCMDB(cfg *config.Config, log *slog.Logger) *cmdb.Resolver {
	switch cfg.CMDBProvider {
	case "":
		return nil
	case "servicenow":
		log.Info("cmdb provider configured", "provider", "servicenow", "url", cfg.CMDBURL, "table", cfg.CMDBTable)
		return cmdb.NewResolver(cmdb.NewServiceNow(cfg.CMDBURL, cfg.CMDBTable, cfg.CMDBSecret), cfg.CMDBCacheTTL)
	case "netbox":
		log.Info("cmdb provider configured", "provider", "netbox", "url", cfg.CMDBURL)
		return cmdb.NewResolver(cmdb.NewNetBox(cfg.CMDBURL, cfg.CMDBSecret), cfg.CMDBCacheTTL)
	default:
		// config.Load validates the enum; this is a defensive default.
		log.Error("unknown CMDB provider ignored", "provider", cfg.CMDBProvider)
		return nil
	}
}

// cmdbReady guards handlers behind provider configuration.
func (s *Server) cmdbReady() error {
	if s.cmdb == nil {
		return apierror.Unavailable("no CMDB provider configured (set PROBECTL_CMDB_PROVIDER)")
	}
	return nil
}

// handleCMDBLookup serves GET /v1/cmdb/lookup?key=<ip|hostname> — a direct,
// RBAC-gated CI lookup (the operator's debugging surface).
func (s *Server) handleCMDBLookup(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	if err := s.cmdbReady(); err != nil {
		return err
	}
	key := cmdb.CanonicalKey(r.URL.Query().Get("key"))
	if key == "" {
		return apierror.BadRequest("key must be an IP address or hostname")
	}
	// DPR-118: the CMDB is ONE deployment-level system shared by every tenant,
	// so an arbitrary key from the query string is not the caller's to ask
	// about. This route used to hand any tenant admin the operator's whole CMDB
	// — on the lab, tenant globex-eu read acme-industries' seeded device. A key
	// is answerable only when the caller already owns something by that name:
	// an agent it enrolled, a device it collects, or a target on one of its own
	// incidents (the contract internal/cmdb documents for every correlation).
	owns, err := s.tenantOwnsCMDBKey(r, key)
	if err != nil {
		return err
	}
	if !owns {
		// Not 403: the answer must not confirm that the key exists somewhere.
		return apierror.NotFound("no configuration item for that key in this tenant")
	}
	cis, lookupErr := s.cmdb.Lookup(r.Context(), key)
	if lookupErr != nil {
		return apierror.Unavailable("CMDB lookup failed (provider unreachable)")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": s.cmdb.ProviderName(), "key": key, "cis": emptyCIs(cis),
	})
	return nil
}

// tenantOwnsCMDBKey reports whether the caller's tenant has an agent, a device
// or an incident target by that name (DPR-118). cmdbKeyOwner is the test seam;
// with no database there is exactly one tenant and nothing to share, so the
// question does not arise.
func (s *Server) tenantOwnsCMDBKey(r *http.Request, key string) (bool, error) {
	if s.cmdbKeyOwner != nil {
		return s.cmdbKeyOwner(r, key)
	}
	if s.pool == nil {
		return true, nil
	}
	var owns bool
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		owns, e = (store.CMDBKeys{}).TenantOwns(ctx, sc, key)
		return e
	})
	return owns, err
}

// handleIncidentCIs serves GET /v1/incidents/{id}/cis — the incident's
// targets (incident + signal targets, tenant-scoped by RLS) correlated to CIs.
func (s *Server) handleIncidentCIs(w http.ResponseWriter, r *http.Request) error {
	if err := s.cmdbReady(); err != nil {
		return err
	}
	id := r.PathValue("id")
	var inc *incident.Incident
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Incidents{}.Get(ctx, sc, id)
		inc = x
		return e
	}); err != nil {
		return err
	}
	matches := s.cmdb.Correlate(r.Context(), incidentKeys(inc))
	writeJSON(w, http.StatusOK, map[string]any{
		"incident_id": inc.ID, "provider": s.cmdb.ProviderName(), "matches": emptyMatches(matches),
	})
	return nil
}

// handleAgentCI serves GET /v1/agents/{id}/ci — the agent (a probectl asset)
// correlated to its CI by hostname.
func (s *Server) handleAgentCI(w http.ResponseWriter, r *http.Request) error {
	if err := s.cmdbReady(); err != nil {
		return err
	}
	id := r.PathValue("id")
	var agent *store.Agent
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		x, e := store.Agents{}.Get(ctx, sc, id)
		agent = x
		return e
	}); err != nil {
		return err
	}
	matches := s.cmdb.Correlate(r.Context(), []string{agent.Hostname, agent.Name})
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id": agent.ID, "provider": s.cmdb.ProviderName(), "matches": emptyMatches(matches),
	})
	return nil
}

// incidentKeys extracts correlation keys from an incident: its target plus
// every signal's target. Prefixes/free-form values are dropped by
// CanonicalKey inside Correlate.
func incidentKeys(inc *incident.Incident) []string {
	keys := []string{inc.Target}
	for _, sig := range inc.Signals {
		keys = append(keys, sig.Target)
	}
	return keys
}

func emptyCIs(cis []cmdb.CI) []cmdb.CI {
	if cis == nil {
		return []cmdb.CI{}
	}
	return cis
}

func emptyMatches(m []cmdb.Match) []cmdb.Match {
	if m == nil {
		return []cmdb.Match{}
	}
	return m
}
