package opendata

import (
	"strings"
	"time"
)

// Public threat-intel feed endpoints (S28).
const (
	urlSpamhausDROP = "https://www.spamhaus.org/drop/drop.txt"
	urlFeodo        = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
	urlSSLBLCerts   = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
	urlSSLBLJA3     = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
	urlURLhaus      = "https://urlhaus.abuse.ch/downloads/csv_recent/"
	urlTorExit      = "https://check.torproject.org/torbulkexitlist"
	urlFireHOL      = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
)

func orDefault(c Doer) Doer {
	if c == nil {
		return defaultIntelClient()
	}
	return c
}

var aupAbuseCh = AUP{License: "abuse.ch (CC0 1.0 Public Domain)", URL: "https://abuse.ch/", CommercialUse: CommercialAllowed}

// NewSpamhausDROP — hijacked / criminal-leased netblocks (CIDR).
func NewSpamhausDROP(client Doer) ThreatIntelSource {
	return &lineFeed{
		desc: Descriptor{Name: "spamhaus_drop", Kind: KindThreatIntel, Cadence: 8 * time.Hour,
			AUP: AUP{License: "Spamhaus DROP (free)", URL: "https://www.spamhaus.org/drop/", Attribution: "Spamhaus DROP", CommercialUse: CommercialAttribution}},
		url: urlSpamhausDROP, client: orDefault(client), parse: spamhausParse,
	}
}

func spamhausParse(line string) (IOC, bool) {
	cidr := line
	if i := strings.IndexByte(cidr, ';'); i >= 0 {
		cidr = strings.TrimSpace(cidr[:i])
	}
	if !strings.Contains(cidr, "/") {
		return IOC{}, false
	}
	return IOC{Type: IOCTypeCIDR, Value: cidr, Source: "spamhaus_drop", Category: CategorySpam, Confidence: 90, License: "Spamhaus DROP"}, true
}

// NewFeodoTracker — botnet C2 IPs (abuse.ch).
func NewFeodoTracker(client Doer) ThreatIntelSource {
	return &lineFeed{
		desc: Descriptor{Name: "feodo_tracker", Kind: KindThreatIntel, Cadence: 1 * time.Hour,
			AUP: aupAbuseCh},
		url: urlFeodo, client: orDefault(client), parse: feodoParse,
	}
}

func feodoParse(line string) (IOC, bool) {
	if strings.ContainsAny(line, " \t,") {
		return IOC{}, false
	}
	return IOC{Type: IOCTypeIP, Value: line, Source: "feodo_tracker", Category: CategoryBotnetC2, Confidence: 90, License: "abuse.ch CC0"}, true
}

// NewSSLBLCerts — malicious-server certificate SHA1 fingerprints (abuse.ch SSLBL).
// The direct tie to S27: a leaf cert matching here is a malicious_cert finding.
func NewSSLBLCerts(client Doer) ThreatIntelSource {
	return &lineFeed{
		desc: Descriptor{Name: "sslbl", Kind: KindThreatIntel, Cadence: 1 * time.Hour, AUP: aupAbuseCh},
		url:  urlSSLBLCerts, client: orDefault(client), parse: sslblCertParse,
	}
}

func sslblCertParse(line string) (IOC, bool) {
	fields := strings.Split(line, ",")
	if len(fields) < 2 {
		return IOC{}, false
	}
	sha1 := strings.ToLower(strings.TrimSpace(fields[1]))
	if len(sha1) != 40 {
		return IOC{}, false
	}
	category := CategoryMaliciousCert
	if len(fields) >= 3 {
		if r := strings.TrimSpace(fields[2]); r != "" {
			category = r
		}
	}
	return IOC{Type: IOCTypeCertSHA1, Value: sha1, Source: "sslbl", Category: category, Confidence: 95, License: "abuse.ch CC0"}, true
}

// NewSSLBLJA3 — malicious JA3 client fingerprints (abuse.ch SSLBL).
func NewSSLBLJA3(client Doer) ThreatIntelSource {
	return &lineFeed{
		desc: Descriptor{Name: "sslbl_ja3", Kind: KindThreatIntel, Cadence: 1 * time.Hour, AUP: aupAbuseCh},
		url:  urlSSLBLJA3, client: orDefault(client), parse: sslblJA3Parse,
	}
}

func sslblJA3Parse(line string) (IOC, bool) {
	fields := strings.Split(line, ",")
	ja3 := strings.ToLower(strings.TrimSpace(fields[0]))
	if len(ja3) != 32 {
		return IOC{}, false
	}
	category := CategoryMaliciousJA3
	if len(fields) >= 4 {
		if r := strings.TrimSpace(fields[3]); r != "" {
			category = r
		}
	}
	return IOC{Type: IOCTypeJA3, Value: ja3, Source: "sslbl_ja3", Category: category, Confidence: 85, License: "abuse.ch CC0"}, true
}

// NewURLhaus — malware-distribution URLs (abuse.ch).
func NewURLhaus(client Doer) ThreatIntelSource {
	return &lineFeed{
		desc: Descriptor{Name: "urlhaus", Kind: KindThreatIntel, Cadence: 1 * time.Hour, AUP: aupAbuseCh},
		url:  urlURLhaus, client: orDefault(client), parse: urlhausParse,
	}
}

func urlhausParse(line string) (IOC, bool) {
	parts := strings.Split(strings.Trim(line, `"`), `","`)
	if len(parts) < 3 {
		return IOC{}, false
	}
	u := strings.TrimSpace(parts[2])
	if !strings.HasPrefix(u, "http") {
		return IOC{}, false
	}
	return IOC{Type: IOCTypeURL, Value: u, Source: "urlhaus", Category: CategoryMalware, Confidence: 85, License: "abuse.ch CC0"}, true
}

// NewTorExit — Tor exit-node IPs (lower confidence: Tor is not inherently
// malicious, but exit traffic is a useful context signal).
func NewTorExit(client Doer) ThreatIntelSource {
	return &lineFeed{
		desc: Descriptor{Name: "tor_exit", Kind: KindThreatIntel, Cadence: 1 * time.Hour,
			AUP: AUP{License: "Tor Project exit list (CC0)", URL: "https://check.torproject.org/", CommercialUse: CommercialAllowed}},
		url: urlTorExit, client: orDefault(client), parse: torParse,
	}
}

func torParse(line string) (IOC, bool) {
	if strings.ContainsAny(line, " \t,") {
		return IOC{}, false
	}
	return IOC{Type: IOCTypeIP, Value: line, Source: "tor_exit", Category: CategoryTorExit, Confidence: 50, License: "Tor Project CC0"}, true
}

// NewFireHOL — FireHOL level-1 aggregate blocklist (IPs + CIDRs). It aggregates
// many feeds with MIXED terms, so its AUP is marked restricted for resale.
func NewFireHOL(client Doer) ThreatIntelSource {
	return &lineFeed{
		desc: Descriptor{Name: "firehol_level1", Kind: KindThreatIntel, Cadence: 4 * time.Hour,
			AUP: AUP{License: "FireHOL blocklist-ipsets (aggregate; mixed terms)", URL: "https://iplists.firehol.org/", CommercialUse: CommercialRestricted, Redistribution: "aggregates upstream feeds with mixed licenses — verify before resale"}},
		url: urlFireHOL, client: orDefault(client), parse: fireholParse,
	}
}

func fireholParse(line string) (IOC, bool) {
	v := strings.TrimSpace(line)
	if strings.ContainsAny(v, " \t,") {
		return IOC{}, false
	}
	if strings.Contains(v, "/") {
		return IOC{Type: IOCTypeCIDR, Value: v, Source: "firehol_level1", Category: CategoryBlocklist, Confidence: 75, License: "FireHOL aggregate"}, true
	}
	return IOC{Type: IOCTypeIP, Value: v, Source: "firehol_level1", Category: CategoryBlocklist, Confidence: 75, License: "FireHOL aggregate"}, true
}

// IntelFeedNames lists the available feed names.
func IntelFeedNames() []string {
	return []string{"spamhaus_drop", "feodo_tracker", "sslbl", "sslbl_ja3", "urlhaus", "tor_exit", "firehol_level1"}
}

// NewIntelFeed builds a feed by name (ok=false if unknown).
func NewIntelFeed(name string, client Doer) (ThreatIntelSource, bool) {
	switch strings.TrimSpace(name) {
	case "spamhaus_drop":
		return NewSpamhausDROP(client), true
	case "feodo_tracker":
		return NewFeodoTracker(client), true
	case "sslbl":
		return NewSSLBLCerts(client), true
	case "sslbl_ja3":
		return NewSSLBLJA3(client), true
	case "urlhaus":
		return NewURLhaus(client), true
	case "tor_exit":
		return NewTorExit(client), true
	case "firehol_level1":
		return NewFireHOL(client), true
	default:
		return nil, false
	}
}

// NewIntelFeeds builds the named feeds (unknown names are skipped).
func NewIntelFeeds(names []string, client Doer) []ThreatIntelSource {
	var out []ThreatIntelSource
	for _, n := range names {
		if f, ok := NewIntelFeed(n, client); ok {
			out = append(out, f)
		}
	}
	return out
}
