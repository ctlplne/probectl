// SPDX-License-Identifier: LicenseRef-probectl-TBD

package threat

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
)

// Threat detections (S-FE3 surface for S28; S42's NDR detections land in the
// same store). A Detection is a confidence-scored SIGNAL with source
// attribution — never a block (CLAUDE.md §7 guardrail 9). Provenance is
// carried verbatim so the surface can be honest about it: threat-intel feeds
// can and do list benign infrastructure.
type Detection struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`     // e.g. "ioc.blocklist", "tls.malicious_cert"; S42 adds e.g. "ndr.beaconing"
	Plane      string    `json:"plane"`    // signal plane ("threat")
	Severity   string    `json:"severity"` // info | warning | critical
	Confidence int       `json:"confidence,omitempty"`
	Source     string    `json:"source,omitempty"`   // the feed / detector that attributed it
	Category   string    `json:"category,omitempty"` // feed category (botnet/tor/blocklist/...)
	Type       string    `json:"type,omitempty"`     // IOC type when intel-backed (ip/cidr/domain/cert_sha1/ja3)
	License    string    `json:"license,omitempty"`  // feed AUP/license tag (provenance)
	Indicator  string    `json:"indicator,omitempty"`
	Entity     string    `json:"entity"` // the flagged thing (IP/host/target)
	Title      string    `json:"title"`
	Summary    string    `json:"summary,omitempty"`
	IncidentID string    `json:"incident_id,omitempty"` // the correlated incident (the triage pivot)
	ObservedAt time.Time `json:"observed_at"`
}

// DetectionFromSignal recognizes a triage-worthy threat-plane signal: anything
// carrying threat-intel provenance (intel.source, S28) or an NDR detector rule
// (detector.rule, S42) — one recognizer, one pipeline. incidentID is the
// correlated incident when ingest succeeded.
func DetectionFromSignal(sig incident.Signal, incidentID string) (Detection, bool) {
	if sig.Plane != "threat" {
		return Detection{}, false
	}
	// NDR behavioral detections (S42): the rule ID is the provenance source,
	// its kind the category, its computed confidence the score. Intel-backed
	// evidence (intel.*) rides along when the detector consulted a feed.
	if rule := sig.Attributes["detector.rule"]; rule != "" {
		conf, _ := strconv.Atoi(sig.Attributes["detector.confidence"])
		category := sig.Attributes["intel.category"]
		if category == "" {
			category = sig.Attributes["detector.kind"]
		}
		return Detection{
			Kind:       sig.Kind,
			Plane:      sig.Plane,
			Severity:   string(sig.Severity),
			Confidence: conf,
			Source:     rule,
			Category:   category,
			Type:       sig.Attributes["intel.type"],
			License:    sig.Attributes["intel.license"],
			Indicator:  sig.Attributes["intel.indicator"],
			Entity:     sig.Target,
			Title:      sig.Title,
			Summary:    sig.Summary,
			IncidentID: incidentID,
			ObservedAt: sig.OccurredAt,
		}, true
	}
	src := sig.Attributes["intel.source"]
	if src == "" {
		return Detection{}, false // not an attributed detection (e.g. plain cert expiry)
	}
	conf, _ := strconv.Atoi(sig.Attributes["intel.confidence"])
	return Detection{
		Kind:       sig.Kind,
		Plane:      sig.Plane,
		Severity:   string(sig.Severity),
		Confidence: conf,
		Source:     src,
		Category:   sig.Attributes["intel.category"],
		Type:       sig.Attributes["intel.type"],
		License:    sig.Attributes["intel.license"],
		Indicator:  sig.Attributes["intel.indicator"],
		Entity:     sig.Target,
		Title:      sig.Title,
		Summary:    sig.Summary,
		IncidentID: incidentID,
		ObservedAt: sig.OccurredAt,
	}, true
}

// DefaultMaxDetectionsPerTenant bounds each tenant's detection partition.
const DefaultMaxDetectionsPerTenant = 1000

// DetectionStore retains recent detections per tenant — newest first, bounded
// (oldest evicted). Like the posture inventory it is in-memory and rebuilt
// from the stream; the durable trail is the incident + SIEM export
// (rebuild-on-restart is the decided contract). Cross-tenant reads are
// impossible by construction (guardrail 1).
type DetectionStore struct {
	mu      sync.Mutex
	max     int
	seq     uint64
	tenants map[string][]Detection // newest first
}

// NewDetectionStore builds a store; maxPerTenant <= 0 takes the default.
func NewDetectionStore(maxPerTenant int) *DetectionStore {
	if maxPerTenant <= 0 {
		maxPerTenant = DefaultMaxDetectionsPerTenant
	}
	return &DetectionStore{max: maxPerTenant, tenants: map[string][]Detection{}}
}

// Record appends a detection to the tenant's partition (assigning its ID).
// Unscoped records are dropped — fail closed, never store cross-tenant data.
func (s *DetectionStore) Record(tenant string, d Detection) {
	if tenant == "" || d.Entity == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	d.ID = fmt.Sprintf("det-%d", s.seq)
	part := s.tenants[tenant]
	part = append([]Detection{d}, part...)
	if len(part) > s.max {
		part = part[:s.max]
	}
	s.tenants[tenant] = part
}

// List returns the tenant's detections, newest first (a copy).
func (s *DetectionStore) List(tenant string) []Detection {
	s.mu.Lock()
	defer s.mu.Unlock()
	part := s.tenants[tenant]
	out := make([]Detection, len(part))
	copy(out, part)
	return out
}

// Len reports one tenant's partition size.
func (s *DetectionStore) Len(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tenants[tenant])
}
