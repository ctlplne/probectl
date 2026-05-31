package crypto

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
)

// TrustDomain is netctl's default SPIFFE trust domain.
const TrustDomain = "netctl"

// SPIFFEID is a tenant-bound agent identity of the form
//
//	spiffe://netctl/tenant/<tenantID>/agent/<agentID>
//
// The agent identity encodes its tenant (PRD §3.2), so the mTLS layer can derive
// the agent's tenant from its verified certificate. SVID issuance is out of scope
// here (S-EE1); this defines the identity shape and how it is read from a cert.
type SPIFFEID struct {
	TrustDomain string
	TenantID    string
	AgentID     string
}

// AgentSPIFFEID builds the SPIFFE URI for a tenant-bound agent.
func AgentSPIFFEID(tenantID, agentID string) string {
	return SPIFFEID{TrustDomain: TrustDomain, TenantID: tenantID, AgentID: agentID}.String()
}

// String renders the SPIFFE URI.
func (id SPIFFEID) String() string {
	return fmt.Sprintf("spiffe://%s/tenant/%s/agent/%s", id.TrustDomain, id.TenantID, id.AgentID)
}

// ParseSPIFFEID parses a netctl agent SPIFFE URI.
func ParseSPIFFEID(uri string) (SPIFFEID, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return SPIFFEID{}, fmt.Errorf("crypto: parse spiffe id: %w", err)
	}
	if u.Scheme != "spiffe" {
		return SPIFFEID{}, fmt.Errorf("crypto: not a spiffe id: %q", uri)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "tenant" || parts[2] != "agent" {
		return SPIFFEID{}, fmt.Errorf("crypto: malformed agent spiffe id: %q", uri)
	}
	return SPIFFEID{TrustDomain: u.Host, TenantID: parts[1], AgentID: parts[3]}, nil
}

// SPIFFEIDFromCert extracts the SPIFFE URI SAN from a (verified) certificate.
func SPIFFEIDFromCert(cert *x509.Certificate) (SPIFFEID, error) {
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			return ParseSPIFFEID(u.String())
		}
	}
	return SPIFFEID{}, fmt.Errorf("crypto: certificate has no SPIFFE URI SAN")
}
