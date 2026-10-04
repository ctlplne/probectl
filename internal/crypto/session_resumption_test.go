// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"context"
	"testing"
	"time"
)

// TestServerTLSConfigsDisableSessionResumption is the SUP-13 / G7-4 regression
// guard: every probectl SERVER TLS config must set SessionTicketsDisabled=true.
// On a resumed TLS handshake Go does NOT re-invoke VerifyPeerCertificate, so the
// custom mTLS checks layered on top of it — SPIFFE trust-domain pinning, the
// live BMP issued-identity registry lookup, and CRL revocation — would be
// silently skipped, letting a client revoked/deregistered after its first
// handshake keep resuming. Forcing a full handshake every time keeps those
// checks on the authentication path.
//
// Fail-before: remove the `cfg.SessionTicketsDisabled = true` line from
// hardenedServerTLS (and the co-located lines in the mTLS builders) and the
// matching assertion(s) here fire.
func TestServerTLSConfigsDisableSessionResumption(t *testing.T) {
	m := mtlsMaterial(t)
	verify := func(context.Context, string, string, string, string) (bool, error) { return true, nil }

	cases := []struct {
		name string
		make func() (disabled bool, hasVerify bool, err error)
	}{
		{"ServerTLSConfig", func() (bool, bool, error) {
			c, err := ServerTLSConfig(m.serverCrt, m.serverKey)
			if err != nil {
				return false, false, err
			}
			return c.SessionTicketsDisabled, c.VerifyPeerCertificate != nil, nil
		}},
		{"ServerMTLSConfig", func() (bool, bool, error) {
			c, err := ServerMTLSConfig(m.serverCrt, m.serverKey, m.caFile)
			if err != nil {
				return false, false, err
			}
			return c.SessionTicketsDisabled, c.VerifyPeerCertificate != nil, nil
		}},
		{"ServerBMPMTLSConfig", func() (bool, bool, error) {
			c, err := ServerBMPMTLSConfig(m.serverCrt, m.serverKey, m.caFile)
			if err != nil {
				return false, false, err
			}
			return c.SessionTicketsDisabled, c.VerifyPeerCertificate != nil, nil
		}},
		{"ServerBMPMTLSConfigRegistered", func() (bool, bool, error) {
			c, err := ServerBMPMTLSConfigRegistered(m.serverCrt, m.serverKey, m.caFile, verify, time.Second)
			if err != nil {
				return false, false, err
			}
			return c.SessionTicketsDisabled, c.VerifyPeerCertificate != nil, nil
		}},
		{"ServerClientCertTLSConfig", func() (bool, bool, error) {
			c, err := ServerClientCertTLSConfig(m.serverCrt, m.serverKey, m.caFile)
			if err != nil {
				return false, false, err
			}
			return c.SessionTicketsDisabled, c.VerifyPeerCertificate != nil, nil
		}},
		{"ServerMTLSConfigRevocable", func() (bool, bool, error) {
			c, err := ServerMTLSConfigRevocable(m.serverCrt, m.serverKey, m.caFile, NewRevocationList())
			if err != nil {
				return false, false, err
			}
			return c.SessionTicketsDisabled, c.VerifyPeerCertificate != nil, nil
		}},
		{"ServerBMPMTLSConfigRegisteredRevocable", func() (bool, bool, error) {
			c, err := ServerBMPMTLSConfigRegisteredRevocable(m.serverCrt, m.serverKey, m.caFile, verify, time.Second, NewRevocationList())
			if err != nil {
				return false, false, err
			}
			return c.SessionTicketsDisabled, c.VerifyPeerCertificate != nil, nil
		}},
	}

	for _, tc := range cases {
		disabled, hasVerify, err := tc.make()
		if err != nil {
			t.Fatalf("%s: build: %v", tc.name, err)
		}
		if !disabled {
			t.Errorf("%s: SessionTicketsDisabled is false — a resumed session would skip the handshake's custom certificate checks (G7-4/SUP-13)", tc.name)
		}
		// Sanity for the configs that carry a CUSTOM VerifyPeerCertificate (the
		// SPIFFE/BMP/revocation hooks resumption would otherwise skip) — this is
		// what the fix protects. ServerTLSConfig (plain HTTPS) and
		// ServerClientCertTLSConfig (third-party senders, standard chain
		// verification, no custom hook) legitimately have none.
		switch tc.name {
		case "ServerTLSConfig", "ServerClientCertTLSConfig":
		default:
			if !hasVerify {
				t.Errorf("%s: expected a custom VerifyPeerCertificate hook (test fixture drift)", tc.name)
			}
		}
	}
}
