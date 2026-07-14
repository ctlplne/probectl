// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

// SPIFFEID is a tenant-bound agent identity of the form
//
//	spiffe://probectl/tenant/<tenantID>/agent/<agentID>
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

// ParseSPIFFEID parses a probectl agent SPIFFE URI. The trust domain is
// PINNED (U-011): an ID under any domain other than TrustDomain is rejected,
// so a syntactically valid SVID from a foreign SPIFFE deployment can never
// parse into a probectl identity — this is the central choke point every
// verify/derivation path (server peer identity, agent self-identity) uses.
func ParseSPIFFEID(uri string) (SPIFFEID, error) {
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
