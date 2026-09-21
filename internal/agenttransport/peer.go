// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/ctlplne/probectl/internal/crypto"
)

// now is the clock every expiry check reads, so a test can move it.
var now = time.Now

// identityFromContext extracts the verified SPIFFE identity from the gRPC peer's
// mTLS client certificate. Because the transport requires and verifies the client
// certificate, this identity is authoritative — it is the agent's tenant + id.
func identityFromContext(ctx context.Context) (crypto.SPIFFEID, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return crypto.SPIFFEID{}, errors.New("no peer in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return crypto.SPIFFEID{}, errors.New("connection is not mTLS")
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return crypto.SPIFFEID{}, errors.New("no client certificate presented")
	}
	leaf := certs[0]
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
