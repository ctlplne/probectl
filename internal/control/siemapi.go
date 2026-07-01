// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/siem"
)

const (
	defaultSIEMAuditPollInterval = 30 * time.Second
	defaultSIEMBufferSize        = 1024
)

type siemStatus struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Summary               string   `json:"summary"`
	SIEMRunning           bool     `json:"siem_running"`
	Enabled               bool     `json:"enabled"`
	Configured            bool     `json:"configured"`
	Reason                string   `json:"reason,omitempty"`
	Preset                string   `json:"preset"`
	Format                string   `json:"format"`
	EndpointConfigured    bool     `json:"endpoint_configured"`
	EndpointTLSConfigured bool     `json:"endpoint_tls_configured"`
	EndpointHost          string   `json:"endpoint_host,omitempty"`
	TokenConfigured       bool     `json:"token_configured"`
	AuditPollInterval     string   `json:"audit_poll_interval"`
	BufferSize            int      `json:"buffer_size"`
	RedactKeyCount        int      `json:"redact_key_count"`
	TLSRequired           bool     `json:"tls_required"`
	NoDropDelivery        bool     `json:"no_drop_delivery"`
	Streams               []string `json:"streams"`
}

func (s *Server) handleSIEMStatus(w http.ResponseWriter, _ *http.Request) error {
	writeJSON(w, http.StatusOK, siemStatusFromConfig(s.cfg))
	return nil
}

func siemStatusFromConfig(cfg *config.Config) siemStatus {
	status := siemStatus{
		ID:                    "siem",
		Name:                  "SIEM export",
		Preset:                string(siem.PresetGeneric),
		Format:                siem.PresetGeneric.DefaultFormat(),
		AuditPollInterval:     defaultSIEMAuditPollInterval.String(),
		BufferSize:            defaultSIEMBufferSize,
		RedactKeyCount:        len(redactionSet(nil)),
		TLSRequired:           true,
		NoDropDelivery:        true,
		Streams:               []string{"audit", "threat"},
		Reason:                "disabled",
		Summary:               "SIEM export is disabled",
		EndpointTLSConfigured: false,
	}
	if cfg == nil {
		return status
	}

	status.Enabled = cfg.SIEMEnabled
	status.TokenConfigured = cfg.SIEMToken != ""
	status.RedactKeyCount = len(redactionSet(cfg.SIEMRedactKeys))
	if cfg.SIEMPollInterval > 0 {
		status.AuditPollInterval = cfg.SIEMPollInterval.String()
	}
	if cfg.SIEMBufferSize > 0 {
		status.BufferSize = cfg.SIEMBufferSize
	}

	preset, ok := siem.ParsePreset(cfg.SIEMPreset)
	if !ok {
		preset = siem.PresetGeneric
	}
	status.Preset = string(preset)
	format := strings.TrimSpace(cfg.SIEMFormat)
	if format == "" {
		format = preset.DefaultFormat()
	}
	formatter, formatOK := siem.NewFormatter(format)
	if formatOK {
		status.Format = formatter.Name()
	} else {
		status.Format = format
	}

	status.EndpointConfigured, status.EndpointTLSConfigured, status.EndpointHost = siemEndpointPosture(cfg.SIEMEndpoint)
	status.Configured = status.Enabled && status.EndpointTLSConfigured && formatOK
	status.SIEMRunning = status.Configured

	switch {
	case !status.Enabled:
		status.Reason = "disabled"
		status.Summary = "SIEM export is disabled"
	case !status.EndpointConfigured:
		status.Reason = "missing_endpoint"
		status.Summary = "SIEM export is enabled but PROBECTL_SIEM_ENDPOINT is empty"
	case !status.EndpointTLSConfigured:
		status.Reason = "insecure_endpoint"
		status.Summary = "SIEM export is enabled but the ingest endpoint is not a valid HTTPS URL"
	case !formatOK:
		status.Reason = "invalid_format"
		status.Summary = "SIEM export is enabled but PROBECTL_SIEM_FORMAT is invalid"
	default:
		status.Reason = "configured"
		status.Summary = "SIEM export is configured for " + status.Preset + "/" + status.Format
		if status.EndpointHost != "" {
			status.Summary += " at " + status.EndpointHost
		}
	}
	return status
}

func siemEndpointPosture(endpoint string) (configured bool, tlsConfigured bool, host string) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return false, false, ""
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return true, false, ""
	}
	return true, endpointTransportAllowed(u), u.Host
}

func endpointTransportAllowed(u *url.URL) bool {
	if u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
