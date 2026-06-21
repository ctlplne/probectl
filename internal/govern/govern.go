// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package govern is the core data-governance mechanism (S-EE3, F34): a data
// CLASSIFICATION taxonomy and a REDACTION/masking engine. The mechanism is
// core (classification + redaction are useful to any deployment — e.g. a
// redacted data export); the per-tenant governance POLICY and its admin
// surface ride ee/ (the `governance` Enterprise feature), installed onto the
// SetSource seam.
//
// The headline classification is IPs-as-PII: under many privacy regimes an IP
// address is personal data, so ip_address defaults to the PII class and is
// redacted by default when redaction is requested. probectl never invents
// attribute names where a standard one exists; the category vocabulary maps to
// the network/OTel fields it already emits.
//
// Governance composes the slices already shipped: classification + redaction
// (here, S-EE3) + retention & cross-store erasure (S-T5, core) + residency
// (S-T2/S-EE2) + BYOK / no-downtime rotation (S-T6). This package owns only
// the new classification/redaction mechanism; the ee/ governance layer ties
// them into one policy + surface.
package govern

import (
	"context"
	"sort"
	"sync"
)

// Class is a data-sensitivity level, ordered low → high. The zero value is
// "unset" (used to mean "inherit the default") so a policy can leave a field
// unconfigured.
type Class int

const (
	ClassUnset        Class = iota // inherit the default
	ClassPublic                    // safe to expose (ASN, public prefix)
	ClassInternal                  // operational, not sensitive (hostname, interface)
	ClassConfidential              // sensitive but not personal (MAC, internal topology)
	ClassPII                       // personal data (IP address, email, geo) — the headline
	ClassRestricted                // secrets / credentials — never exported in clear
)

// String renders a class as its stable lowercase token.
func (c Class) String() string {
	switch c {
	case ClassPublic:
		return "public"
	case ClassInternal:
		return "internal"
	case ClassConfidential:
		return "confidential"
	case ClassPII:
		return "pii"
	case ClassRestricted:
		return "restricted"
	default:
		return "unset"
	}
}

// ParseClass parses a class token (unknown → ClassUnset).
func ParseClass(s string) Class {
	switch s {
	case "public":
		return ClassPublic
	case "internal":
		return ClassInternal
	case "confidential":
		return ClassConfidential
	case "pii":
		return ClassPII
	case "restricted":
		return ClassRestricted
	default:
		return ClassUnset
	}
}

// Category is a kind of data value (not a column name) — the unit that gets
// classified and redacted. Categories map to the network/OTel fields probectl
// emits.
type Category string

const (
	CatIPAddress    Category = "ip_address"    // IPv4/IPv6 — PII by default (the headline)
	CatEmail        Category = "email"         // PII
	CatSubjectID    Category = "subject_id"    // user/account/session identifiers — PII
	CatFreeText     Category = "free_text"     // log bodies, AI questions/answers, JSON payload text — PII-scanned
	CatAttributeMap Category = "attribute_map" // OTLP attrs/resource maps — recursively classified
	CatDNSName      Category = "dns_name"      // qname/resource names may contain user/host identity — PII
	CatURLPath      Category = "url_path"      // path segments often carry subject IDs — PII
	CatObjectKey    Category = "object_key"    // object/export/support-bundle keys — PII
	CatGeo          Category = "geo"           // city/region/coords — PII
	CatMAC          Category = "mac_address"   // Confidential
	CatWorkload     Category = "workload_name" // service/workload labels — Confidential
	CatOrgUnit      Category = "org_unit"      // department/team/org attributes — Confidential
	CatHostname     Category = "hostname"      // Internal
	CatUserAgent    Category = "user_agent"    // Internal
	CatASN          Category = "asn"           // Public
	CatCredential   Category = "credential"    // Restricted (secrets/tokens)
)

// defaultClass is the built-in classification: IPs-as-PII is the headline.
var defaultClass = map[Category]Class{
	CatIPAddress:    ClassPII,
	CatEmail:        ClassPII,
	CatSubjectID:    ClassPII,
	CatFreeText:     ClassPII,
	CatAttributeMap: ClassPII,
	CatDNSName:      ClassPII,
	CatURLPath:      ClassPII,
	CatObjectKey:    ClassPII,
	CatGeo:          ClassPII,
	CatMAC:          ClassConfidential,
	CatWorkload:     ClassConfidential,
	CatOrgUnit:      ClassConfidential,
	CatHostname:     ClassInternal,
	CatUserAgent:    ClassInternal,
	CatASN:          ClassPublic,
	CatCredential:   ClassRestricted,
}

// Policy is a tenant's governance policy for classification + redaction. The
// retention/residency/BYOK fields are recorded here for the COMPOSED
// governance view, but enforcement is delegated to their owners (S-T5 / S-T2 /
// S-T6) — this package only owns classification + redaction.
type Policy struct {
	// Overrides re-classify categories for this tenant (e.g. treat hostname as
	// Confidential). Empty = the built-in defaults.
	Overrides map[Category]Class `json:"overrides,omitempty"`
	// Strategy per class. A class with no entry uses the default for its level
	// (>= RedactFrom → Partial). ClassRestricted always drops in clear.
	Strategies map[Class]Strategy `json:"strategies,omitempty"`
	// RedactFrom is the lowest class redacted when redaction is active. Unset
	// (zero) means the deployment default (ClassPII) is used.
	RedactFrom Class `json:"redact_from,omitempty"`
	// RedactExport forces the portability export to be redacted even when the
	// request did not ask for it (a strict-tenant default).
	RedactExport bool `json:"redact_export,omitempty"`

	// AIRemoteEgress is the tenant's consent for sending its telemetry to a
	// REMOTE AI model (U-013). Default false; enforced by the analyzer.
	AIRemoteEgress bool `json:"ai_remote_egress,omitempty"`

	// Composed (delegated) governance, recorded for the unified view only:
	RetentionDays *int   `json:"retention_days,omitempty"` // S-T5
	Residency     string `json:"residency,omitempty"`      // S-T2 / S-EE2
}

// ClassOf returns the effective class of a category under this policy.
func (p Policy) ClassOf(cat Category) Class {
	if c, ok := p.Overrides[cat]; ok && c != ClassUnset {
		return c
	}
	if c, ok := defaultClass[cat]; ok {
		return c
	}
	return ClassInternal // unknown categories are operational by default
}

// redactFrom resolves the effective lowest-redacted class.
func (p Policy) redactFrom() Class {
	if p.RedactFrom != ClassUnset {
		return p.RedactFrom
	}
	return ClassPII // the default: redact PII and above
}

// StrategyFor returns how a category is masked under this policy. Categories
// below RedactFrom are not redacted (StrategyNone). Restricted always drops.
func (p Policy) StrategyFor(cat Category) Strategy {
	cls := p.ClassOf(cat)
	if cls < p.redactFrom() {
		return StrategyNone
	}
	if cls == ClassRestricted {
		return StrategyDrop
	}
	if s, ok := p.Strategies[cls]; ok {
		return s
	}
	return StrategyPartial
}

// DefaultPIIPolicy redacts PII and above with partial masking — the policy
// used when a redacted export is requested but the tenant configured nothing
// (the core mechanism works without the governance feature).
func DefaultPIIPolicy() Policy {
	return Policy{RedactFrom: ClassPII}
}

// PolicySource resolves a tenant's stored governance policy (ee/governance).
// ok=false = no per-tenant policy (defaults apply).
type PolicySource interface {
	PolicyFor(ctx context.Context, tenantID string) (Policy, bool, error)
}

var (
	mu     sync.RWMutex
	source PolicySource
)

// SetSource installs the per-tenant policy source (the ee/governance attach
// seam). nil clears it (defaults for everyone).
func SetSource(s PolicySource) {
	mu.Lock()
	defer mu.Unlock()
	source = s
}

// Reset clears the source (tests).
func Reset() { SetSource(nil) }

// PolicyFor returns a tenant's effective policy. With no source installed (or
// no per-tenant row), the zero policy applies — which redacts NOTHING until a
// caller asks (e.g. a redacted export uses DefaultPIIPolicy). A source error
// degrades to the default (availability over strictness for a read path).
func PolicyFor(ctx context.Context, tenantID string) Policy {
	mu.RLock()
	s := source
	mu.RUnlock()
	if s == nil {
		return Policy{}
	}
	if p, ok, err := s.PolicyFor(ctx, tenantID); err == nil && ok {
		return p
	}
	return Policy{}
}

// Categories lists the known categories (sorted) — the governance surface.
func Categories() []Category {
	out := make([]Category, 0, len(defaultClass))
	for c := range defaultClass {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DefaultClassOf is the built-in class of a category (no policy).
func DefaultClassOf(cat Category) Class { return Policy{}.ClassOf(cat) }
