// SPDX-License-Identifier: LicenseRef-probectl-TBD

package threat

import (
	"fmt"
	"strconv"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// ToSignals maps a posture into threat-plane incident signals — one per finding —
// so the TLS/cert plane feeds the unified timeline + alerting (S16/S17), with the
// trustctl handoff carried in attributes. Returns nothing for a clean posture.
func ToSignals(tenantID string, p Posture) []incident.Signal {
	if len(p.Findings) == 0 {
		return nil
	}
	base := map[string]string{
		"tls.version":      p.TLSVersion,
		"tls.cipher.suite": p.Cipher, // ARCH-001: OTel standard name (was tls.cipher)
		"source":           p.Source,
	}
	if p.Leaf != nil {
		base["cert.subject"] = p.Leaf.Subject
		base["cert.issuer"] = p.Leaf.Issuer
		base["cert.not_after"] = p.Leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	if p.Handoff != nil && p.Handoff.URL != "" {
		base["trustctl.handoff_url"] = p.Handoff.URL
	}

	out := make([]incident.Signal, 0, len(p.Findings))
	for _, f := range p.Findings {
		attrs := make(map[string]string, len(base)+3)
		for k, v := range base {
			attrs[k] = v
		}
		// Threat-intel provenance (S28): a match carries its feed + confidence so
		// the analyst sees WHY it fired and can tune/suppress it (signal, not block).
		if f.Source != "" {
			attrs["intel.source"] = f.Source
			attrs["intel.confidence"] = strconv.Itoa(f.Confidence)
			if f.Type != "" {
				attrs["intel.type"] = f.Type
			}
			if f.Category != "" {
				attrs["intel.category"] = f.Category
			}
			if f.License != "" {
				attrs["intel.license"] = f.License
			}
			if f.Indicator != "" {
				attrs["intel.indicator"] = f.Indicator
			}
		}
		out = append(out, incident.Signal{
			TenantID:   tenantID,
			Plane:      "threat",
			Kind:       "tls." + string(f.Kind),
			Severity:   incident.Severity(f.Severity),
			Title:      f.Message,
			Summary:    fmt.Sprintf("%s: %s", p.Target, f.Message),
			Target:     p.Target,
			Attributes: attrs,
			OccurredAt: p.ObservedAt,
		})
	}
	return out
}
