package opendata

// IOCType classifies a threat-intel indicator of compromise (S28).
type IOCType string

const (
	IOCTypeIP       IOCType = "ip"
	IOCTypeCIDR     IOCType = "cidr"
	IOCTypeDomain   IOCType = "domain"
	IOCTypeURL      IOCType = "url"
	IOCTypeCertSHA1 IOCType = "cert_sha1"
	IOCTypeJA3      IOCType = "ja3"
)

// IOC categories (free-form; these are the common ones across feeds).
const (
	CategoryBotnetC2      = "botnet_c2"
	CategoryMalware       = "malware"
	CategoryMaliciousCert = "malicious_cert"
	CategoryMaliciousJA3  = "malicious_ja3"
	CategorySpam          = "spam"
	CategoryTorExit       = "tor_exit"
	CategoryScanner       = "scanner"
	CategoryBlocklist     = "blocklist"
)

// IOC is one normalized indicator from a threat-intel feed.
type IOC struct {
	Type       IOCType `json:"type"`
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	Category   string  `json:"category,omitempty"`
	Confidence int     `json:"confidence"` // 0..100
	License    string  `json:"license,omitempty"`
}

// IOCMatch is a hit when scoring a target against the IOC store — it carries
// source attribution + confidence (the S28 contract).
type IOCMatch struct {
	Type       IOCType `json:"type"`
	Indicator  string  `json:"indicator"` // the matched IOC value (e.g. the CIDR that contained the IP)
	Source     string  `json:"source"`
	Category   string  `json:"category,omitempty"`
	Confidence int     `json:"confidence"`
	License    string  `json:"license,omitempty"`
}
