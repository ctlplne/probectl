package otlp

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ErrUnauthenticated is returned by an Authenticator for a missing/invalid token.
var ErrUnauthenticated = errors.New("otlp: unauthenticated")

// Authenticator resolves an OTLP bearer token to the tenant it is scoped to.
type Authenticator interface {
	Authenticate(token string) (tenant string, err error)
}

// TokenAuthenticator maps static bearer tokens to tenants (PROBECTL_OTLP_TOKENS).
// Tokens are bearer secrets carried over TLS; production may additionally use
// mTLS / SPIFFE identity (the transport already requires TLS).
type TokenAuthenticator struct {
	tokens map[string]string
}

// NewTokenAuthenticator builds an authenticator from token→tenant pairs (empty
// keys/values are dropped).
func NewTokenAuthenticator(tokenToTenant map[string]string) *TokenAuthenticator {
	cp := make(map[string]string, len(tokenToTenant))
	for k, v := range tokenToTenant {
		if k != "" && v != "" {
			cp[k] = v
		}
	}
	return &TokenAuthenticator{tokens: cp}
}

// Authenticate resolves a token to its tenant, failing closed.
func (a *TokenAuthenticator) Authenticate(token string) (string, error) {
	if token == "" {
		return "", ErrUnauthenticated
	}
	if t, ok := a.tokens[token]; ok {
		return t, nil
	}
	return "", ErrUnauthenticated
}

type tenantKey struct{}

func withTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

func tenantFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(tenantKey{}).(string)
	return t, ok && t != ""
}

// authUnaryInterceptor authenticates each RPC's bearer token and puts the
// resolved tenant on the context; it fails closed with Unauthenticated.
func authUnaryInterceptor(auth Authenticator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		tenant, err := auth.Authenticate(bearerFromMetadata(ctx))
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "otlp: invalid or missing bearer token")
		}
		return handler(withTenant(ctx, tenant), req)
	}
}

func bearerFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ""
	}
	return bearerFromHeader(vals[0])
}

func bearerFromHeader(authz string) string {
	return strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
}
