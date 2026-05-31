package agenttransport

import (
	"context"
	"errors"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/imfeelingtheagi/netctl/internal/crypto"
)

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
	return crypto.SPIFFEIDFromCert(certs[0])
}
