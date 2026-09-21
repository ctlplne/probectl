// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// TrustDomain is probectl's default SPIFFE trust domain.
const TrustDomain = "probectl"

// SPIFFEID is a tenant-bound registered workload identity of the form
//
//	spiffe://probectl/tenant/<tenantID>/<plane>/<agentID>
//
// Plane is deliberately restricted to an identity shape owned by the existing
// enrollment registry. Agent and BMP identities share issuance/revocation
// storage, but their TLS listeners use plane-specific parsers so one plane's
// credential cannot authenticate to another plane.
type SPIFFEID struct {
	TrustDomain string
	TenantID    string
	AgentID     string
	Plane       string
}

// AgentSPIFFEID builds the SPIFFE URI for a tenant-bound agent.
func AgentSPIFFEID(tenantID, agentID string) string {
	return SPIFFEID{TrustDomain: TrustDomain, TenantID: tenantID, AgentID: agentID, Plane: "agent"}.String()
}

// BMPSPIFFEID builds the SPIFFE URI for a registry-issued BMP router.
func BMPSPIFFEID(tenantID, routerID string) string {
	return SPIFFEID{TrustDomain: TrustDomain, TenantID: tenantID, AgentID: routerID, Plane: "bmp"}.String()
}

// String renders the SPIFFE URI.
func (id SPIFFEID) String() string {
	plane := id.Plane
	if plane == "" {
		plane = "agent"
	}
	return fmt.Sprintf("spiffe://%s/tenant/%s/%s/%s", id.TrustDomain, id.TenantID, plane, id.AgentID)
}

// ParseSPIFFEID parses a probectl agent SPIFFE URI. The trust domain is
// PINNED (U-011): an ID under any domain other than TrustDomain is rejected,
// so a syntactically valid SVID from a foreign SPIFFE deployment can never
// parse into a probectl identity — this is the central choke point every
// verify/derivation path (server peer identity, agent self-identity) uses.
func ParseSPIFFEID(uri string) (SPIFFEID, error) {
	return parseSPIFFEIDForPlane(uri, "agent")
}

// ParseBMPSPIFFEID parses only a probectl BMP-router SPIFFE URI. Keeping this
// separate from ParseSPIFFEID prevents a bmp credential from authenticating to
// the agent transport, even though both identities use the same registry.
func ParseBMPSPIFFEID(uri string) (SPIFFEID, error) {
	return parseSPIFFEIDForPlane(uri, "bmp")
}

func parseSPIFFEIDForPlane(uri, plane string) (SPIFFEID, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return SPIFFEID{}, fmt.Errorf("crypto: parse spiffe id: %w", err)
	}
	if u.Scheme != "spiffe" {
		return SPIFFEID{}, fmt.Errorf("crypto: not a spiffe id: %q", uri)
	}
	if u.Host != TrustDomain {
		return SPIFFEID{}, fmt.Errorf("crypto: foreign spiffe trust domain %q (pinned to %q)", u.Host, TrustDomain)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Contains(uri, "#") {
		return SPIFFEID{}, fmt.Errorf(
			"crypto: spiffe id contains userinfo, query, or fragment: %q",
			uri,
		)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "tenant" || parts[1] == "" ||
		parts[1] == "." || parts[1] == ".." ||
		parts[2] != plane || parts[3] == "" ||
		parts[3] == "." || parts[3] == ".." {
		return SPIFFEID{}, fmt.Errorf("crypto: malformed %s spiffe id: %q", plane, uri)
	}
	id := SPIFFEID{
		TrustDomain: u.Host,
		TenantID:    parts[1],
		AgentID:     parts[3],
		Plane:       plane,
	}
	if u.String() != uri || id.String() != uri {
		return SPIFFEID{}, fmt.Errorf(
			"crypto: non-canonical %s spiffe id: %q",
			plane,
			uri,
		)
	}
	return id, nil
}

// SPIFFEIDFromCert extracts the single canonical SPIFFE URI SAN from a
// (verified) certificate.
func SPIFFEIDFromCert(cert *x509.Certificate) (SPIFFEID, error) {
	return spiffeIDFromCert(cert, ParseSPIFFEID)
}

// BMPSPIFFEIDFromCert extracts one canonical BMP-router URI SAN.
func BMPSPIFFEIDFromCert(cert *x509.Certificate) (SPIFFEID, error) {
	return spiffeIDFromCert(cert, ParseBMPSPIFFEID)
}

// RegisteredSPIFFEIDFromCert extracts either supported enrollment-registry
// identity. Plane-specific listener authentication must use the narrower
// helper above; this broader helper is for shared rotation and revocation.
func RegisteredSPIFFEIDFromCert(cert *x509.Certificate) (SPIFFEID, error) {
	if id, err := SPIFFEIDFromCert(cert); err == nil {
		return id, nil
	}
	return BMPSPIFFEIDFromCert(cert)
}

func spiffeIDFromCert(cert *x509.Certificate, parse func(string) (SPIFFEID, error)) (SPIFFEID, error) {
	if cert == nil {
		return SPIFFEID{}, fmt.Errorf("crypto: certificate is required")
	}
	if len(cert.URIs) != 1 || cert.URIs[0] == nil {
		return SPIFFEID{}, fmt.Errorf(
			"crypto: certificate must have exactly one URI SAN containing a canonical SPIFFE ID",
		)
	}
	return parse(cert.URIs[0].String())
}

// SPIFFEIDFromCertFile reads the first certificate in a PEM file and returns its
// SPIFFE identity. An agent uses this to learn its own tenant + id from its
// client certificate.
func SPIFFEIDFromCertFile(path string) (SPIFFEID, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return SPIFFEID{}, fmt.Errorf("crypto: read certificate: %w", err)
	}
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return SPIFFEID{}, fmt.Errorf("crypto: no certificate in %s", path)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return SPIFFEID{}, fmt.Errorf("crypto: parse certificate: %w", err)
		}
		return SPIFFEIDFromCert(cert)
	}
}
