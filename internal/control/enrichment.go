// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/opendata"
)

// BuildEnrichment builds the shared open-data enricher from every configured
// source, or (nil, false) when none is. Registration order is precedence:
// local-file sources first (most precise, no egress — air-gap friendly), the
// Team Cymru DNS fallback after them, and PeeringDB last because it keys on
// the ASN Cymru resolves. A configured source whose local data cannot be
// loaded is registered unavailable — visible in GET /v1/threat/intel/status
// with the load error — and the control plane keeps serving (open data
// degrades gracefully, CLAUDE.md §7 guardrail 10).
func BuildEnrichment(cfg *config.Config, log *slog.Logger) (*opendata.Enricher, bool) {
	if !cfg.FlowEnrichASN && cfg.FlowEnrichGeoDB == "" && cfg.FlowEnrichRIRDir == "" && !cfg.FlowEnrichIXP {
		return nil, false
	}
	en := opendata.NewEnricher(log, opendata.WithCacheMaxEntries(cfg.FlowEnrichCacheMax))
	if cfg.FlowEnrichGeoDB != "" {
		if reader, err := opendata.OpenMMDB(cfg.FlowEnrichGeoDB); err != nil {
			log.Error("geo enrichment configured but unavailable", "error", err)
			en.RegisterUnavailable(opendata.NewGeo(nil), err)
		} else {
			en.Register(opendata.NewGeo(reader))
			log.Info("geo enrichment enabled", "source", "maxmind-geolite2")
		}
	}
	if cfg.FlowEnrichRIRDir != "" {
		if idx, files, err := opendata.LoadRIRDir(cfg.FlowEnrichRIRDir); err != nil {
			log.Error("RIR allocation enrichment configured but unavailable", "error", err)
			en.RegisterUnavailable(opendata.NewRIRAllocations(), err)
		} else {
			v4, v6 := idx.Size()
			en.Register(idx)
			log.Info("RIR allocation enrichment enabled", "source", "rir-stats",
				"files", files, "v4_ranges", v4, "v6_prefixes", v6)
		}
	}
	if cfg.FlowEnrichASN {
		en.Register(opendata.NewCymru(net.DefaultResolver))
		log.Info("ASN enrichment enabled", "source", "team-cymru")
	}
	if cfg.FlowEnrichIXP {
		en.Register(opendata.NewPeeringDB(nil))
		log.Info("IXP enrichment enabled", "source", "peeringdb")
	}
	return en, true
}

// handleOpenDataEnrichment serves GET /v1/opendata/enrichment?ip=<addr> — the
// full open-data context for one IP (ASN, geo, RIR allocation, IXP presence)
// with per-source provenance. The payload is shared public-dataset context
// about a public address; no tenant-owned data appears in it. Lookups go
// through the shared cache, identical to the flow ingest path.
func (s *Server) handleOpenDataEnrichment(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	if s.openDataEnricher == nil {
		return apierror.Unavailable("no open-data enrichment source configured (set PROBECTL_FLOW_ENRICH_ASN, _GEOIP_DB, _RIR_DIR or _IXP)")
	}
	ip := r.URL.Query().Get("ip")
	if _, err := netip.ParseAddr(ip); err != nil {
		return apierror.BadRequest("ip must be a valid IPv4 or IPv6 address")
	}
	e, err := s.openDataEnricher.Enrich(r.Context(), ip)
	if err != nil {
		return apierror.BadRequest("ip must be a valid IPv4 or IPv6 address")
	}
	writeJSON(w, http.StatusOK, e)
	return nil
}
