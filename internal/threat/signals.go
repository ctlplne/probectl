package threat

import (
	"fmt"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/incident"
)

// ToSignals maps a posture into threat-plane incident signals — one per finding —
// so the TLS/cert plane feeds the unified timeline + alerting (S16/S17), with the
// certctl handoff carried in attributes. Returns nothing for a clean posture.
func ToSignals(tenantID string, p Posture) []incident.Signal {
	if len(p.Findings) == 0 {
		return nil
	}
	base := map[string]string{
		"tls.version": p.TLSVersion,
		"tls.cipher":  p.Cipher,
		"source":      p.Source,
	}
	if p.Leaf != nil {
		base["cert.subject"] = p.Leaf.Subject
		base["cert.issuer"] = p.Leaf.Issuer
		base["cert.not_after"] = p.Leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	if p.Handoff != nil && p.Handoff.URL != "" {
		base["certctl.handoff_url"] = p.Handoff.URL
	}

	out := make([]incident.Signal, 0, len(p.Findings))
	for _, f := range p.Findings {
		attrs := make(map[string]string, len(base))
		for k, v := range base {
			attrs[k] = v
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
