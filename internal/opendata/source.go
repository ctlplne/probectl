// Package opendata is netctl's open-data enrichment framework (S15): a pluggable
// set of sources that annotate an IP with ASN / geo / IXP / allocation context
// drawn from public datasets, with per-source provenance + AUP metadata, caching,
// and graceful degradation.
//
// Tenancy: open data is NOT tenant-owned. It is ingested once and shared across
// tenants; the Enricher is tenant-agnostic and returns plain data that the caller
// attaches to a tenant-scoped record (a flow/test result), so the tenant boundary
// is enforced where the enrichment is stored, not in this package (PRD §3 — shared
// once, scoped per tenant). External fetches are over TLS with certificate
// validation and treated as untrusted (CLAUDE.md §7 guardrails 10, 12). A source
// that is disabled or failing is logged and skipped — it must never break a core
// path (graceful degradation).
package opendata

import (
	"context"
	"net/netip"
	"time"
)

// Kind classifies what a source contributes.
type Kind string

const (
	KindASN         Kind = "asn"         // IP → ASN / prefix / registry
	KindGeo         Kind = "geo"         // IP → country / city / lat-lon
	KindIXP         Kind = "ixp"         // ASN → IXP / facility presence
	KindAllocation  Kind = "allocation"  // IP → RIR allocation / status
	KindMeasurement Kind = "measurement" // active measurement scheduling (RIPE Atlas)
)

// Permission expresses a source's commercial-use terms (relevant to MSP resale —
// CLAUDE.md §2; not to private development or single-tenant OSS use).
type Permission string

const (
	CommercialAllowed     Permission = "allowed"
	CommercialAttribution Permission = "allowed-with-attribution"
	CommercialRestricted  Permission = "restricted"
	CommercialUnknown     Permission = "unknown"
)

// AUP is a source's acceptable-use / licensing provenance, tracked per source so
// the operator (and a future MSP reseller) can see exactly what each dataset
// permits.
type AUP struct {
	License        string     // e.g. "CC BY-SA 4.0"
	URL            string     // terms / homepage
	Attribution    string     // required attribution text, if any
	CommercialUse  Permission // for reseller/commercial use
	Redistribution string     // notes on redistribution limits
}

// Descriptor is the static identity of a source — the OpenDataSource model
// (type, cadence, AUP/provenance). Mutable runtime health lives in Health.
type Descriptor struct {
	Name    string
	Kind    Kind
	Cadence time.Duration // how often the underlying dataset is refreshed
	AUP     AUP
}

// Health is a source's mutable runtime status, tracked by the Enricher.
type Health struct {
	Enabled     bool
	Status      string // "ok" | "degraded" | "failed" | "disabled"
	LastSuccess time.Time
	LastError   string
}

// Source is an enrichment plugin. Enrich looks up addr and contributes ONLY its
// own fields to e (other sources fill the rest); it returns an error on failure,
// which the Enricher logs and skips. Implementations must not panic and must
// respect ctx cancellation/deadline.
type Source interface {
	Descriptor() Descriptor
	Enrich(ctx context.Context, addr netip.Addr, e *Enrichment) error
}

// Provenance records that a source contributed to an Enrichment, with its license
// + attribution, so each enriched record can be traced to its datasets.
type Provenance struct {
	Source      string   `json:"source"`
	License     string   `json:"license,omitempty"`
	Attribution string   `json:"attribution,omitempty"`
	Fields      []string `json:"fields,omitempty"`
}

// IXP is an internet-exchange / facility presence for an ASN.
type IXP struct {
	Name   string `json:"name"`
	IXID   int    `json:"ix_id,omitempty"`
	IPv4   string `json:"ipv4,omitempty"`
	IPv6   string `json:"ipv6,omitempty"`
	SpeedM int    `json:"speed_mbit,omitempty"`
}

// Enrichment is the open-data context attached to an IP — the contract the flow
// and test planes consume. Zero-valued fields mean "no source provided this".
type Enrichment struct {
	IP               string       `json:"ip"`
	ASN              uint32       `json:"asn,omitempty"`
	ASName           string       `json:"as_name,omitempty"`
	Prefix           string       `json:"prefix,omitempty"`
	CountryCode      string       `json:"country_code,omitempty"`
	City             string       `json:"city,omitempty"`
	Latitude         float64      `json:"latitude,omitempty"`
	Longitude        float64      `json:"longitude,omitempty"`
	RIR              string       `json:"rir,omitempty"`
	AllocationStatus string       `json:"allocation_status,omitempty"`
	AllocationDate   string       `json:"allocation_date,omitempty"`
	IXPs             []IXP        `json:"ixps,omitempty"`
	Sources          []Provenance `json:"sources,omitempty"`
}

// addProvenance records a source's contribution.
func (e *Enrichment) addProvenance(d Descriptor, fields ...string) {
	e.Sources = append(e.Sources, Provenance{
		Source:      d.Name,
		License:     d.AUP.License,
		Attribution: d.AUP.Attribution,
		Fields:      fields,
	})
}
