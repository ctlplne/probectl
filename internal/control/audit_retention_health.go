// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

type auditRetentionHealth struct {
	Status                          string   `json:"status"`
	Enabled                         bool     `json:"enabled"`
	RawRowsAgingOut                 bool     `json:"raw_rows_aging_out"`
	TenantRowsAgingOut              bool     `json:"tenant_rows_aging_out"`
	ProviderRowsAgingOut            bool     `json:"provider_rows_aging_out"`
	Window                          string   `json:"window,omitempty"`
	WindowSeconds                   int64    `json:"window_seconds,omitempty"`
	TenantSIEMWatermarkConfigured   bool     `json:"tenant_siem_watermark_configured"`
	ProviderWORMWatermarkConfigured bool     `json:"provider_worm_watermark_configured"`
	Notes                           []string `json:"notes,omitempty"`
}

func (s *Server) auditRetentionHealth() auditRetentionHealth {
	h := auditRetentionHealth{Status: "disabled"}
	if s == nil || s.cfg == nil || s.cfg.AuditRetention <= 0 {
		h.Notes = []string{"raw in-DB audit rows are not age-pruned; subject erasure is projected on read/export only"}
		return h
	}

	h.Enabled = true
	h.Window = s.cfg.AuditRetention.String()
	h.WindowSeconds = int64(s.cfg.AuditRetention.Seconds())
	h.TenantSIEMWatermarkConfigured = s.cfg.SIEMEnabled && s.cfg.SIEMEndpoint != ""
	h.ProviderWORMWatermarkConfigured = s.cfg.AuditWORMDir != ""
	h.TenantRowsAgingOut = h.TenantSIEMWatermarkConfigured
	h.ProviderRowsAgingOut = h.ProviderWORMWatermarkConfigured
	h.RawRowsAgingOut = h.TenantRowsAgingOut && h.ProviderRowsAgingOut

	switch {
	case h.RawRowsAgingOut:
		h.Status = "armed"
	case h.TenantRowsAgingOut || h.ProviderRowsAgingOut:
		h.Status = "partial"
	default:
		h.Status = "blocked"
	}
	if !h.TenantRowsAgingOut {
		h.Notes = append(h.Notes, "tenant audit rows will not age out until SIEM delivery watermarks are configured")
	}
	if !h.ProviderRowsAgingOut {
		h.Notes = append(h.Notes, "provider/break-glass audit rows will not age out until WORM export watermarks are configured")
	}
	return h
}

func (s *Server) registerAuditRetentionMetrics() {
	if s == nil || s.metrics == nil {
		return
	}
	s.metrics.Gauge("probectl_audit_retention_window_seconds",
		"Configured raw audit retention window in seconds; 0 means in-DB audit rows are not age-pruned.",
		func() float64 {
			if s.cfg == nil || s.cfg.AuditRetention <= 0 {
				return 0
			}
			return s.cfg.AuditRetention.Seconds()
		})
	s.metrics.Gauge("probectl_audit_retention_raw_rows_aging_out",
		"1 when tenant and provider raw audit rows have the export-watermark configuration needed to age out; 0 means disabled, blocked, or partial.",
		func() float64 {
			if s.auditRetentionHealth().RawRowsAgingOut {
				return 1
			}
			return 0
		})
}
