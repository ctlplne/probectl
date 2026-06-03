// Package siem exports netctl's audit + security events to a SOC's SIEM (S32,
// F26). It is the forwarder: a canonical Event, pluggable Formatters (RFC 5424
// syslog, ArcSight CEF, Elastic ECS, OTLP logs), preset-aware HTTP/syslog Senders
// (Splunk HEC, Microsoft Sentinel, Elastic, Google Chronicle), and a buffered,
// retrying Forwarder that does NOT drop events under backpressure. The package is
// pure — the control plane maps audit.Event + incident.Signal onto siem.Event and
// drives the forwarder; netctl is never itself a SIEM (out of scope).
package siem

import "time"

// Severity is a normalized event severity.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// cef maps to the CEF 0..10 severity scale.
func (s Severity) cef() int {
	switch s {
	case SeverityCritical:
		return 9
	case SeverityWarning:
		return 6
	default:
		return 3
	}
}

// syslog maps to the RFC 5424 severity (0=emerg..7=debug).
func (s Severity) syslog() int {
	switch s {
	case SeverityCritical:
		return 2 // critical
	case SeverityWarning:
		return 4 // warning
	default:
		return 6 // informational
	}
}

// otlpNumber maps to the OTLP severity number (1..24).
func (s Severity) otlpNumber() int {
	switch s {
	case SeverityCritical:
		return 21 // ERROR3
	case SeverityWarning:
		return 13 // WARN
	default:
		return 9 // INFO
	}
}

// Category groups events for the SIEM (ECS event.category / CEF deviceEventClass).
type Category string

const (
	CategoryAudit  Category = "audit"
	CategoryThreat Category = "threat"
	CategoryChange Category = "configuration"
)

// Event is the canonical record forwarded to a SIEM. Attributes carry the
// event-specific detail; the control plane fills them from the audit Data or the
// incident Signal attributes (after PII redaction).
type Event struct {
	Time       time.Time
	TenantID   string
	Category   Category
	Action     string // e.g. "alert.create", "tls.cert_expired", "ioc.botnet_c2"
	Severity   Severity
	Actor      string // who/what caused it (audit actor, or "scim"/"webhook:…")
	Target     string // affected resource (id / host / prefix)
	Outcome    string // "success" | "failure" | "" (unknown)
	Message    string
	Attributes map[string]string
}

func (e Event) time() time.Time {
	if e.Time.IsZero() {
		return time.Now().UTC()
	}
	return e.Time.UTC()
}

func (e Event) message() string {
	if e.Message != "" {
		return e.Message
	}
	return string(e.Category) + " " + e.Action
}
