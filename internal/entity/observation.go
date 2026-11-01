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
	// A sender-bound collector may observe only identifiers from its own
	// configured source family. Otherwise a compromised flow or BMP collector
	// could author an SNMP/interface or site alias against its operator anchor.
	switch o.Source.Kind {
	case DeviceTarget:
		switch o.Alias.Kind {
		case AddressAlias, PrefixAlias, SNMPDeviceAlias, SNMPInterfaceAlias, PhysicalNeighborAlias:
		default:
			return Observation{}, ErrInvalidClaim
		}
	case FlowExporter:
		if o.Alias.Kind != AddressAlias && o.Alias.Kind != FlowExporterAlias {
			return Observation{}, ErrInvalidClaim
		}
		addr, err := netip.ParseAddr(o.Source.SourceRef)
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() ||
			addr.Unmap().String() != o.Source.SourceRef {
			return Observation{}, ErrInvalidClaim
		}
		if o.Alias.Kind == AddressAlias && o.Alias.Value != o.Source.SourceRef {
			return Observation{}, ErrInvalidClaim
		}
		if o.Alias.Kind == FlowExporterAlias {
			prefix := o.Source.SourceRef + "/"
			if !strings.HasPrefix(o.Alias.Value, prefix) {
				return Observation{}, ErrInvalidClaim
			}
			parts := strings.Split(strings.TrimPrefix(o.Alias.Value, prefix), "/")
			if len(parts) != 2 {
				return Observation{}, ErrInvalidClaim
			}
			switch parts[0] {
			case "netflow5", "netflow9", "ipfix", "sflow5":
			default:
				return Observation{}, ErrInvalidClaim
			}
			domain, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil || strconv.FormatUint(domain, 10) != parts[1] {
				return Observation{}, ErrInvalidClaim
			}
			if strings.TrimSpace(o.SourceRef) != "flow:"+parts[0]+":domain:"+parts[1] {
				return Observation{}, ErrInvalidClaim
			}
		}
	case BMPPeer:
		if o.Alias.Kind != AddressAlias && o.Alias.Kind != BMPPeerAlias {
			return Observation{}, ErrInvalidClaim
		}
		provenance := "bmp:router:" + o.Source.SourceRef + ":peer-asn:"
		if !strings.HasPrefix(strings.TrimSpace(o.SourceRef), provenance) {
			return Observation{}, ErrInvalidClaim
		}
		asnText := strings.TrimPrefix(strings.TrimSpace(o.SourceRef), provenance)
		asn, err := strconv.ParseUint(asnText, 10, 32)
		if err != nil || strconv.FormatUint(asn, 10) != asnText {
			return Observation{}, ErrInvalidClaim
		}
		if o.Alias.Kind == BMPPeerAlias {
			index := strings.LastIndex(o.Alias.Value, "/as")
			if index < 1 || o.Alias.Value[index+3:] != asnText {
				return Observation{}, ErrInvalidClaim
			}
			addr, err := netip.ParseAddr(o.Alias.Value[:index])
			if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() ||
				addr.Unmap().String() != o.Alias.Value[:index] {
				return Observation{}, ErrInvalidClaim
			}
		}
	case PathAgent:
		if o.Alias.Kind != AddressAlias && o.Alias.Kind != PathHopAlias {
			return Observation{}, ErrInvalidClaim
		}
	case AgentSite:
		if o.Alias.Kind != AgentSiteAlias {
			return Observation{}, ErrInvalidClaim
		}
		if o.Source.SourceRef != o.Source.AgentID ||
			strings.TrimSpace(o.SourceRef) != "agent:label:site" {
			return Observation{}, ErrInvalidClaim
		}
	default:
		return Observation{}, ErrInvalidClaim
	}
	o.SourceRef = strings.TrimSpace(o.SourceRef)
	if o.SourceRef == "" || len(o.SourceRef) > 1024 ||
		strings.IndexFunc(o.SourceRef, unicode.IsControl) >= 0 {
		return Observation{}, ErrInvalidClaim
	}
	o.OriginSerial = strings.TrimSpace(o.OriginSerial)
	if o.Source.Kind == BMPPeer {
		if len(o.OriginSerial) == 0 || len(o.OriginSerial) > 128 ||
			strings.IndexFunc(o.OriginSerial, func(r rune) bool {
				return r < '0' || (r > '9' && r < 'a') || r > 'f'
			}) >= 0 {
			return Observation{}, ErrInvalidClaim
		}
	} else if o.OriginSerial != "" {
		return Observation{}, ErrInvalidClaim
	}
	if o.Alias.Kind == SNMPInterfaceAlias {
		if o.Source.Kind != DeviceTarget ||
			o.SourceRef != "snmp:ifIndex:"+o.Alias.Value ||
			len(o.InterfaceName) > 1024 ||
			len(o.InterfaceDescription) > 1024 ||
			!utf8.ValidString(o.InterfaceName) ||
			!utf8.ValidString(o.InterfaceDescription) ||
			strings.IndexFunc(o.InterfaceName, unicode.IsControl) >= 0 ||
			strings.IndexFunc(o.InterfaceDescription, unicode.IsControl) >= 0 {
			return Observation{}, ErrInvalidClaim
		}
	} else if o.InterfaceName != "" || o.InterfaceDescription != "" {
		return Observation{}, ErrInvalidClaim
	}
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
	if o.ObservedAt.IsZero() || o.ObservedAt.After(now.Add(5*time.Minute)) ||
		o.ObservedAt.Before(now.Add(-7*24*time.Hour)) {
		return Observation{}, ErrInvalidClaim
	}
	// PostgreSQL timestamps store microseconds. Canonicalize before the
	// idempotency comparison so a nanosecond input replays identically.
	o.ObservedAt = o.ObservedAt.UTC().Truncate(time.Microsecond)
	return o, nil
}
