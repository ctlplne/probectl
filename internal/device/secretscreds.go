package device

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// ResolveSecret resolves one raw credential value that MAY be a secret
// reference (S41): literals pass through, references hit a secret backend.
// It is satisfied by (*secrets.Resolver).Resolve — the seam keeps this
// package free of a hard dependency and the tests hermetic.
type ResolveSecret func(ctx context.Context, raw string) (string, error)

// SecretsCredentials is the S41 secrets-backed CredentialSource: the same
// PROBECTL_DEVICE_CRED_<NAME>_* environment layout as EnvCredentials, except
// each field VALUE may be a secret reference —
//
//	PROBECTL_DEVICE_CRED_CORE_COMMUNITY=vault:kv/netops/snmp#community
//	PROBECTL_DEVICE_CRED_CORE_PASSWORD=aws:prod/gnmi#password
//
// so no secret material sits in the environment or config, only references.
// Every Resolve call re-resolves through the backend's lease cache, which is
// how rotated-upstream credentials are picked up between polls (short-lived
// leases). Any backend failure FAILS CLOSED: an error, never a stale or
// partial credential (the S41 'watch out for').
type SecretsCredentials struct {
	getenv  func(string) string
	resolve ResolveSecret
	timeout time.Duration
}

// NewSecretsCredentials builds the secrets-backed source. getenv nil defaults
// to os.Getenv; resolve is required (callers wire secrets.Resolver.Resolve).
func NewSecretsCredentials(getenv func(string) string, resolve ResolveSecret) (*SecretsCredentials, error) {
	if resolve == nil {
		return nil, fmt.Errorf("device: secrets credentials need a resolver")
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	return &SecretsCredentials{getenv: getenv, resolve: resolve, timeout: 15 * time.Second}, nil
}

// Resolve implements CredentialSource: read the env layout, then resolve each
// non-empty field through the secrets resolver (references resolve, literals
// pass through). The first failing field fails the whole credential.
func (s *SecretsCredentials) Resolve(name string) (Credential, error) {
	key := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToUpper(name))
	pfx := "PROBECTL_DEVICE_CRED_" + key + "_"
	raw := map[string]string{
		"COMMUNITY":  s.getenv(pfx + "COMMUNITY"),
		"USERNAME":   s.getenv(pfx + "USERNAME"),
		"AUTH_PROTO": s.getenv(pfx + "AUTH_PROTO"),
		"AUTH_PASS":  s.getenv(pfx + "AUTH_PASS"),
		"PRIV_PROTO": s.getenv(pfx + "PRIV_PROTO"),
		"PRIV_PASS":  s.getenv(pfx + "PRIV_PASS"),
		"PASSWORD":   s.getenv(pfx + "PASSWORD"),
	}
	empty := true
	for _, v := range raw {
		if v != "" {
			empty = false
			break
		}
	}
	if empty {
		return Credential{}, fmt.Errorf("device: credential %q not found (set %s* env vars; values may be secret references)", name, pfx)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	out := map[string]string{}
	for field, v := range raw {
		if v == "" {
			continue
		}
		resolved, err := s.resolve(ctx, v)
		if err != nil {
			// Fail closed; the error from the resolver is already redacted.
			return Credential{}, fmt.Errorf("device: credential %q field %s: %w", name, field, err)
		}
		out[field] = resolved
	}
	return Credential{
		Community: out["COMMUNITY"],
		Username:  out["USERNAME"],
		AuthProto: strings.ToLower(out["AUTH_PROTO"]),
		AuthPass:  out["AUTH_PASS"],
		PrivProto: strings.ToLower(out["PRIV_PROTO"]),
		PrivPass:  out["PRIV_PASS"],
		Password:  out["PASSWORD"],
	}, nil
}
