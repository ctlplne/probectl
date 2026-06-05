package control

// Editions wiring (S-T0): the license manager loads once at startup (a
// configured-but-invalid license fails startup; absent = Community) and the
// Admin → Editions endpoint serves license truth — the ONE place tiers
// appear when unlicensed (the hidden-unlicensed UX, ratified June 2026).
// Feature gating for ee/ functionality happens at the main.go Build* seams
// via lic.Has/Mode — never here, never in handlers.

import (
	"log/slog"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/license"
)

// BuildLicense loads the license per config. Empty path = Community (the
// default-open free core). Invalid/forged/missing-but-configured = startup
// ERROR (fail closed on configuration); expired loads fine and degrades per
// the grace ladder.
func BuildLicense(cfg *config.Config, log *slog.Logger) (*license.Manager, error) {
	path := ""
	if cfg != nil {
		path = cfg.LicenseFile
	}
	m, err := license.Load(path, license.TrustedKeys())
	if err != nil {
		return nil, err
	}
	if log != nil && m.Tier() != license.TierCommunity {
		info := m.Info()
		log.Info("license loaded",
			"tier", info.Tier, "state", info.State, "customer", info.Customer,
			"expires_at", info.ExpiresAt, "tenant_band", info.TenantBand)
	}
	return m, nil
}

// WithLicense attaches the license manager backing /v1/editions. nil falls
// back to Community (default-open).
func (s *Server) WithLicense(m *license.Manager) *Server {
	if m != nil {
		s.license = m
	}
	return s
}

// licenseManager returns the attached manager or the Community default.
func (s *Server) licenseManager() *license.Manager {
	if s.license != nil {
		return s.license
	}
	return license.Community()
}

// handleEditions serves GET /v1/editions — tier, lifecycle state, expiry
// horizon, the full feature table with per-feature licensed/mode truth, and
// the FIPS posture (S-EE1: a compliance/status INDICATOR only — FIPS is a
// hardening build, gated by the artifact, never a runtime license check).
func (s *Server) handleEditions(w http.ResponseWriter, r *http.Request) error {
	if _, err := s.principalTenant(r); err != nil {
		return err
	}
	type editionsView struct {
		license.Info
		FIPS crypto.FIPSStatus `json:"fips"`
	}
	writeJSON(w, http.StatusOK, editionsView{
		Info: s.licenseManager().Info(),
		FIPS: crypto.Status(),
	})
	return nil
}
