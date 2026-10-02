// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/ctlplne/probectl/internal/crypto"
)

// now is the clock every expiry check reads, so a test can move it.
var now = time.Now

// peerLeafFromContext returns the verified mTLS client leaf certificate from the
// gRPC peer. The transport requires and verifies the client certificate, so the
// leaf is authoritative. Both the identity derivation (below) and the per-call
// revocation recheck (CRY-01) read it, so the extraction lives in one place.
func peerLeafFromContext(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("no peer in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("connection is not mTLS")
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no client certificate presented")
	}
	return certs[0], nil
}

// identityFromContext extracts the verified SPIFFE identity from the gRPC peer's
// mTLS client certificate. Because the transport requires and verifies the client
// certificate, this identity is authoritative — it is the agent's tenant + id.
func identityFromContext(ctx context.Context) (crypto.SPIFFEID, error) {
	leaf, err := peerLeafFromContext(ctx)
	if err != nil {
		return crypto.SPIFFEID{}, err
	}
	// DPR-175: TLS checks the certificate ONCE, at the handshake. The agent lane
	// is a long-lived bidirectional stream, so an SVID that expires mid-stream
	// keeps being accepted until something unrelated breaks the connection — on
	// the lab that was 8.5 hours of heartbeats after expiry, with the fleet view
	// reporting the agent ready the whole time. A short-lived identity whose real
	// lifetime is "until the next reconnect" is not a short-lived identity, and
	// guardrail §7.4/§7.12 says an invalid credential fails closed. Every call
	// re-reads the expiry its own certificate was issued with.
	if t := now(); t.After(leaf.NotAfter) {
		return crypto.SPIFFEID{}, fmt.Errorf(
			"agent identity expired at %s (rotate before expiry via POST /enroll/agent/rotate; an expired identity must re-enroll with a join token)",
			leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return crypto.SPIFFEIDFromCert(leaf)
}

// authenticate resolves the verified agent identity and re-validates it on EVERY
// call. identityFromContext already re-reads certificate EXPIRY mid-stream
// (DPR-175); this additionally re-reads the registry REVOCATION deny-list
// (CRY-01). mTLS consults that deny-list only ONCE, at the handshake
// (crypto.revocationGuard, U-038), so an agent revoked AFTER its long-lived
// bidirectional stream was established keeps attesting, heart-beating and
// streaming results until its short-lived certificate expires — on the lab that
// was the full remainder of the cert lifetime, with the operator believing the
// revocation had taken hold. The deny-list here is the SAME pointer the control
// plane refreshes from the agent registry (Server.RevocationList(): the periodic
// reload and the immediate operator push), so the NEXT Attest/Heartbeat/
// StreamResults on that connection is refused within one refresh interval.
// Guardrail §7.4/§7.12: a revoked credential fails closed on every path.
func (svc *service) authenticate(ctx context.Context) (crypto.SPIFFEID, error) {
	id, err := identityFromContext(ctx)
	if err != nil {
		return crypto.SPIFFEID{}, err
	}
	rl := svc.revocations
	if rl == nil || rl.Empty() {
		// Hot path: nothing revoked (the steady state) — no extra work beyond
		// the cheap identity read every handler already does.
		return id, nil
	}
	leaf, err := peerLeafFromContext(ctx)
	if err != nil {
		return crypto.SPIFFEID{}, err
	}
	// Match the handshake guard: deny by serial OR by SPIFFE id, so revoking the
	// identity catches a re-issued cert too (the no-resurrection guarantee).
	sid := ""
	if registered, rerr := crypto.RegisteredSPIFFEIDFromCert(leaf); rerr == nil {
		sid = registered.String()
	}
	if rl.IsRevoked(leaf.SerialNumber.Text(16), sid) {
		return crypto.SPIFFEID{}, fmt.Errorf(
			"agent certificate REVOKED (serial %s) — refused mid-stream; re-enroll with a join token after remediation (CRY-01)",
			leaf.SerialNumber.Text(16))
	}
	return id, nil
}
