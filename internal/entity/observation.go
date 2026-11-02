// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Observation is an untrusted collector claim. The authenticated mTLS peer
// supplies AgentID; an operator mapping supplies context and canonical entity.
// Neither field is accepted from this structure.
type Observation struct {
	ID        string
	Source    SourceKey
	Alias     AliasKey
	SourceRef string
	// OriginSerial is the exact verified router SVID serial for BMP only.
	// A listener cannot make queued evidence current after that certificate
	// is revoked or replaced.
	OriginSerial string
	// InterfaceName and InterfaceDescription are observational SNMP labels,
	// never identity keys or routing context selectors.
	InterfaceName        string
	InterfaceDescription string
	// SystemDescription is SNMP sysDescr on the configured-target address
	// observation only. It never identifies an entity or selects a context.
	SystemDescription    string
	NeighborProtocol     string
	NeighborLocalIfIndex uint32
	NeighborLocalPortID  string
	NeighborRemotePortID string
	NeighborChassisID    string
	NeighborDeviceName   string
	NeighborAddress      string
	ObservedAt           time.Time
}

// NormalizeObservation checks the bounded identity fields before any tenant
// transaction. Freshness is relative to the receiver's clock, not a collector
// clock used as an authority for routing or tenancy.
func (o Observation) Normalize(now time.Time) (Observation, error) {
	id, err := uuid.Parse(o.ID)
	if err != nil || id == uuid.Nil || id.Version() != 4 {
		return Observation{}, ErrInvalidClaim
	}
	o.ID = id.String()
	o.Source, err = o.Source.Normalize()
	if err != nil {
		return Observation{}, err
	}
	o.Alias, err = o.Alias.Normalize()
	if err != nil {
		return Observation{}, err
	}
	// A sender-bound collector may observe only its configured source family.
	if err := validateObservationFamily(o); err != nil {
		return Observation{}, err
	}
	o.SourceRef = strings.TrimSpace(o.SourceRef)
	if o.SourceRef == "" || len(o.SourceRef) > 1024 ||
		strings.IndexFunc(o.SourceRef, unicode.IsControl) >= 0 {
		return Observation{}, ErrInvalidClaim
	}
	o.OriginSerial = strings.TrimSpace(o.OriginSerial)
	if err := validateOriginSerial(o); err != nil {
		return Observation{}, err
	}
	if err := validateInterfaceObservation(o); err != nil {
		return Observation{}, err
	}
	if o.SystemDescription != "" && (o.Source.Kind != DeviceTarget ||
		o.Alias.Kind != AddressAlias || o.SourceRef != "snmp:configured-target" ||
		len(o.SystemDescription) > 1024 || !utf8.ValidString(o.SystemDescription) ||
		strings.IndexFunc(o.SystemDescription, invalidSystemDescriptionControl) >= 0) {
		return Observation{}, ErrInvalidClaim
	}
	o, err = normalizeNeighborObservation(o)
	if err != nil {
		return Observation{}, err
	}
	if o.ObservedAt.IsZero() || o.ObservedAt.After(now.Add(5*time.Minute)) ||
		o.ObservedAt.Before(now.Add(-7*24*time.Hour)) {
		return Observation{}, ErrInvalidClaim
	}
	// PostgreSQL timestamps store microseconds. Canonicalize before the
	// idempotency comparison so a nanosecond input replays identically.
	o.ObservedAt = o.ObservedAt.UTC().Truncate(time.Microsecond)
	return o, nil
}

// DisplayString permits horizontal tabs and line breaks. Preserve those
// observational bytes; other controls cannot enter metadata or rule facts.
func invalidSystemDescriptionControl(r rune) bool {
	return unicode.IsControl(r) && r != '\t' && r != '\r' && r != '\n'
}

func validateObservationFamily(o Observation) error {
	switch o.Source.Kind {
	case DeviceTarget:
		switch o.Alias.Kind {
		case AddressAlias, PrefixAlias, SNMPDeviceAlias, SNMPInterfaceAlias, PhysicalNeighborAlias:
			return nil
		}
	case FlowExporter:
		return validateFlowObservation(o)
	case BMPPeer:
		return validateBMPObservation(o)
	case PathAgent:
		if o.Alias.Kind == AddressAlias || o.Alias.Kind == PathHopAlias {
			return nil
		}
	case AgentSite:
		if o.Alias.Kind == AgentSiteAlias && o.Source.SourceRef == o.Source.AgentID &&
			strings.TrimSpace(o.SourceRef) == "agent:label:site" {
			return nil
		}
	}
	return ErrInvalidClaim
}

func validateFlowObservation(o Observation) error {
	if o.Alias.Kind != AddressAlias && o.Alias.Kind != FlowExporterAlias {
		return ErrInvalidClaim
	}
	addr, err := netip.ParseAddr(o.Source.SourceRef)
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() ||
		addr.Unmap().String() != o.Source.SourceRef {
		return ErrInvalidClaim
	}
	if o.Alias.Kind == AddressAlias {
		if o.Alias.Value != o.Source.SourceRef {
			return ErrInvalidClaim
		}
		return nil
	}
	prefix := o.Source.SourceRef + "/"
	if !strings.HasPrefix(o.Alias.Value, prefix) {
		return ErrInvalidClaim
	}
	parts := strings.Split(strings.TrimPrefix(o.Alias.Value, prefix), "/")
	if len(parts) != 2 {
		return ErrInvalidClaim
	}
	switch parts[0] {
	case "netflow5", "netflow9", "ipfix", "sflow5":
	default:
		return ErrInvalidClaim
	}
	domain, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || strconv.FormatUint(domain, 10) != parts[1] ||
		strings.TrimSpace(o.SourceRef) != "flow:"+parts[0]+":domain:"+parts[1] {
		return ErrInvalidClaim
	}
	return nil
}

func validateBMPObservation(o Observation) error {
	if o.Alias.Kind != AddressAlias && o.Alias.Kind != BMPPeerAlias {
		return ErrInvalidClaim
	}
	provenance := "bmp:router:" + o.Source.SourceRef + ":peer-asn:"
	if !strings.HasPrefix(strings.TrimSpace(o.SourceRef), provenance) {
		return ErrInvalidClaim
	}
	asnText := strings.TrimPrefix(strings.TrimSpace(o.SourceRef), provenance)
	asn, err := strconv.ParseUint(asnText, 10, 32)
	if err != nil || strconv.FormatUint(asn, 10) != asnText {
		return ErrInvalidClaim
	}
	if o.Alias.Kind == BMPPeerAlias {
		index := strings.LastIndex(o.Alias.Value, "/as")
		if index < 1 || o.Alias.Value[index+3:] != asnText {
			return ErrInvalidClaim
		}
		addr, err := netip.ParseAddr(o.Alias.Value[:index])
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() ||
			addr.Unmap().String() != o.Alias.Value[:index] {
			return ErrInvalidClaim
		}
	}
	return nil
}

func validateOriginSerial(o Observation) error {
	if o.Source.Kind == BMPPeer {
		if len(o.OriginSerial) == 0 || len(o.OriginSerial) > 128 ||
			strings.IndexFunc(o.OriginSerial, func(r rune) bool {
				return r < '0' || (r > '9' && r < 'a') || r > 'f'
			}) >= 0 {
			return ErrInvalidClaim
		}
	} else if o.OriginSerial != "" {
		return ErrInvalidClaim
	}
	return nil
}

func validateInterfaceObservation(o Observation) error {
	if o.Alias.Kind == SNMPInterfaceAlias {
		if o.Source.Kind != DeviceTarget ||
			o.SourceRef != "snmp:ifIndex:"+o.Alias.Value ||
			len(o.InterfaceName) > 1024 ||
			len(o.InterfaceDescription) > 1024 ||
			!utf8.ValidString(o.InterfaceName) ||
			!utf8.ValidString(o.InterfaceDescription) ||
			strings.IndexFunc(o.InterfaceName, unicode.IsControl) >= 0 ||
			strings.IndexFunc(o.InterfaceDescription, unicode.IsControl) >= 0 {
			return ErrInvalidClaim
		}
	} else if o.InterfaceName != "" || o.InterfaceDescription != "" {
		return ErrInvalidClaim
	}
	return nil
}

func normalizeNeighborObservation(o Observation) (Observation, error) {
	if o.Alias.Kind == PhysicalNeighborAlias {
		if o.Source.Kind != DeviceTarget || o.Alias.Value != o.SourceRef ||
			!strings.HasPrefix(o.SourceRef, "neighbor:") ||
			(o.NeighborProtocol != "lldp" && o.NeighborProtocol != "cdp") ||
			o.NeighborLocalIfIndex == 0 || o.NeighborLocalPortID == "" ||
			o.NeighborRemotePortID == "" ||
			(o.NeighborAddress == "" && o.NeighborDeviceName == "") {
			return Observation{}, ErrInvalidClaim
		}
		for _, value := range []string{o.NeighborLocalPortID, o.NeighborRemotePortID,
			o.NeighborChassisID, o.NeighborDeviceName} {
			if len(value) > 256 || !utf8.ValidString(value) ||
				strings.IndexFunc(value, unicode.IsControl) >= 0 {
				return Observation{}, ErrInvalidClaim
			}
		}
		if o.NeighborAddress != "" {
			addr, err := netip.ParseAddr(o.NeighborAddress)
			if err != nil || addr.Zone() != "" {
				return Observation{}, ErrInvalidClaim
			}
			o.NeighborAddress = addr.Unmap().String()
		}
	} else if o.NeighborProtocol != "" || o.NeighborLocalIfIndex != 0 ||
		o.NeighborLocalPortID != "" || o.NeighborRemotePortID != "" ||
		o.NeighborChassisID != "" || o.NeighborDeviceName != "" ||
		o.NeighborAddress != "" {
		return Observation{}, ErrInvalidClaim
	}
	return o, nil
}
