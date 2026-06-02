package opendata

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// IOCStore is the shared, tenant-agnostic indicator store (S28). Feeds load IOCs
// into it (the index is rebuilt atomically on refresh); the threat plane scores
// flows / connections / DNS / certs against it. Open threat-intel is ingested
// ONCE and shared across tenants; a match is stored on a tenant-scoped record, so
// the tenant boundary is enforced where the match lands, not here (PRD §3).
type IOCStore struct {
	mu      sync.RWMutex
	ips     map[string]IOCMatch
	domains map[string]IOCMatch
	urls    map[string]IOCMatch
	certs   map[string]IOCMatch // SHA1, lowercase hex
	ja3     map[string]IOCMatch
	cidrs   []cidrEntry
	sources map[string]int // source name -> ioc count
}

type cidrEntry struct {
	prefix netip.Prefix
	match  IOCMatch
}

// NewIOCStore returns an empty store.
func NewIOCStore() *IOCStore {
	return &IOCStore{
		ips: map[string]IOCMatch{}, domains: map[string]IOCMatch{}, urls: map[string]IOCMatch{},
		certs: map[string]IOCMatch{}, ja3: map[string]IOCMatch{}, sources: map[string]int{},
	}
}

func toMatch(i IOC) IOCMatch {
	return IOCMatch{Type: i.Type, Indicator: i.Value, Source: i.Source, Category: i.Category, Confidence: i.Confidence, License: i.License}
}

// Load atomically rebuilds the index from the union of IOCs (across all sources).
// Malformed indicators are skipped (the feed body is untrusted input).
func (s *IOCStore) Load(iocs []IOC) {
	ips := map[string]IOCMatch{}
	domains := map[string]IOCMatch{}
	urls := map[string]IOCMatch{}
	certs := map[string]IOCMatch{}
	ja3 := map[string]IOCMatch{}
	var cidrs []cidrEntry
	counts := map[string]int{}

	for _, i := range iocs {
		m := toMatch(i)
		ok := true
		switch i.Type {
		case IOCTypeIP:
			if addr, err := netip.ParseAddr(i.Value); err == nil {
				ips[addr.String()] = m
			} else {
				ok = false
			}
		case IOCTypeCIDR:
			if p, err := netip.ParsePrefix(i.Value); err == nil {
				cidrs = append(cidrs, cidrEntry{prefix: p.Masked(), match: m})
			} else {
				ok = false
			}
		case IOCTypeDomain:
			domains[strings.ToLower(strings.TrimSuffix(i.Value, "."))] = m
		case IOCTypeURL:
			urls[strings.TrimSpace(i.Value)] = m
		case IOCTypeCertSHA1:
			certs[strings.ToLower(i.Value)] = m
		case IOCTypeJA3:
			ja3[strings.ToLower(i.Value)] = m
		default:
			ok = false
		}
		if ok {
			counts[i.Source]++
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ips, s.domains, s.urls, s.certs, s.ja3, s.cidrs, s.sources = ips, domains, urls, certs, ja3, cidrs, counts
}

// ScoreIP returns matches for an IP — an exact hit plus any containing CIDR.
func (s *IOCStore) ScoreIP(ip string) []IOCMatch {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []IOCMatch
	if m, ok := s.ips[addr.String()]; ok {
		out = append(out, m)
	}
	for _, c := range s.cidrs {
		if c.prefix.Contains(addr) {
			out = append(out, c.match)
		}
	}
	return out
}

// ScoreDomain returns a match for a domain (exact, lowercased).
func (s *IOCStore) ScoreDomain(domain string) []IOCMatch {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.domains[d]; ok {
		return []IOCMatch{m}
	}
	return nil
}

// ScoreURL returns a match for an exact URL.
func (s *IOCStore) ScoreURL(url string) []IOCMatch {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.urls[strings.TrimSpace(url)]; ok {
		return []IOCMatch{m}
	}
	return nil
}

// ScoreCert returns matches for a certificate SHA1 and/or a JA3 fingerprint — the
// SSLBL tie to the S27 TLS observer.
func (s *IOCStore) ScoreCert(sha1, ja3Fingerprint string) []IOCMatch {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []IOCMatch
	if sha1 != "" {
		if m, ok := s.certs[strings.ToLower(sha1)]; ok {
			out = append(out, m)
		}
	}
	if ja3Fingerprint != "" {
		if m, ok := s.ja3[strings.ToLower(ja3Fingerprint)]; ok {
			out = append(out, m)
		}
	}
	return out
}

// Count returns the total number of indicators loaded.
func (s *IOCStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, c := range s.sources {
		n += c
	}
	return n
}

// Sources returns the per-source indicator counts, sorted by name (the operator
// status / AUP matrix).
func (s *IOCStore) Sources() []SourceCount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SourceCount, 0, len(s.sources))
	for name, n := range s.sources {
		out = append(out, SourceCount{Source: name, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

// SourceCount is one feed's contribution to the store.
type SourceCount struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}
