package opendata

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// TXTResolver looks up DNS TXT records. It is injectable so the Team Cymru source
// is testable without DNS; *net.Resolver satisfies it.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// cymruSource maps an IP to its origin ASN, prefix, registry, and AS name using
// the Team Cymru IP-to-ASN DNS service (the canonical real-time lookup).
type cymruSource struct {
	resolver TXTResolver
}

// NewCymru builds the Team Cymru IP→ASN source over the given TXT resolver.
func NewCymru(resolver TXTResolver) Source {
	return &cymruSource{resolver: resolver}
}

func (c *cymruSource) Descriptor() Descriptor {
	return Descriptor{
		Name:    "team-cymru",
		Kind:    KindASN,
		Cadence: time.Hour,
		AUP: AUP{
			License:       "Team Cymru community service (free)",
			URL:           "https://team-cymru.com/community-services/ip-asn-mapping/",
			Attribution:   "IP-to-ASN mapping by Team Cymru",
			CommercialUse: CommercialAttribution,
		},
	}
}

func (c *cymruSource) Enrich(ctx context.Context, addr netip.Addr, e *Enrichment) error {
	txts, err := c.resolver.LookupTXT(ctx, cymruOriginName(addr))
	if err != nil {
		return fmt.Errorf("cymru origin lookup: %w", err)
	}
	asn, prefix, cc, registry, ok := parseCymruOrigin(txts)
	if !ok {
		return nil // no mapping for this IP — absence is not a failure
	}

	fields := []string{"asn"}
	if e.ASN == 0 {
		e.ASN = asn
	}
	if e.Prefix == "" && prefix != "" {
		e.Prefix = prefix
		fields = append(fields, "prefix")
	}
	if e.CountryCode == "" && cc != "" {
		e.CountryCode = cc
		fields = append(fields, "country_code")
	}
	if e.RIR == "" && registry != "" {
		e.RIR = registry
		fields = append(fields, "rir")
	}
	if e.ASName == "" {
		if name, ok := c.asName(ctx, asn); ok {
			e.ASName = name
			fields = append(fields, "as_name")
		}
	}
	e.addProvenance(c.Descriptor(), fields...)
	return nil
}

// cymruOriginName builds the reverse-DNS query name for an address under the
// Team Cymru origin zone.
func cymruOriginName(addr netip.Addr) string {
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	}
	b := addr.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0x0f, b[i]>>4)
	}
	sb.WriteString("origin6.asn.cymru.com")
	return sb.String()
}

// parseCymruOrigin parses an origin TXT record:
//
//	"13335 | 1.1.1.0/24 | US | arin | 2010-07-14"
//
// The ASN field may list several origins (e.g. "23028 13335"); the first is used.
func parseCymruOrigin(txts []string) (asn uint32, prefix, cc, registry string, ok bool) {
	if len(txts) == 0 {
		return 0, "", "", "", false
	}
	parts := strings.Split(txts[0], "|")
	if len(parts) < 4 {
		return 0, "", "", "", false
	}
	origins := strings.Fields(strings.TrimSpace(parts[0]))
	if len(origins) == 0 {
		return 0, "", "", "", false
	}
	n, err := strconv.ParseUint(origins[0], 10, 32)
	if err != nil {
		return 0, "", "", "", false
	}
	return uint32(n),
		strings.TrimSpace(parts[1]),
		strings.ToUpper(strings.TrimSpace(parts[2])),
		strings.ToLower(strings.TrimSpace(parts[3])),
		true
}

// asName resolves an ASN to its name via the Cymru AS zone:
//
//	"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
func (c *cymruSource) asName(ctx context.Context, asn uint32) (string, bool) {
	txts, err := c.resolver.LookupTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asn))
	if err != nil || len(txts) == 0 {
		return "", false
	}
	parts := strings.Split(txts[0], "|")
	if len(parts) < 5 {
		return "", false
	}
	name := strings.TrimSpace(parts[4])
	return name, name != ""
}
