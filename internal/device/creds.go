package device

import (
	"fmt"
	"os"
	"strings"
)

// Credential carries the secrets for one device transport. Config files
// reference credentials by NAME; the material itself lives behind a
// CredentialSource (CLAUDE.md §7 guardrail 6 — no secrets in config or git).
// The String/GoString overrides keep credentials out of logs and %v dumps.
type Credential struct {
	// SNMP v2c.
	Community string
	// SNMP v3 (USM). AuthProto: sha | sha256 | md5; PrivProto: aes | aes256 | des.
	Username  string
	AuthProto string
	AuthPass  string
	PrivProto string
	PrivPass  string
	// gNMI metadata authentication (optional; TLS client auth is preferred).
	Password string
}

// String redacts everything (slog/%v safety — guardrail 6: never log secrets).
func (Credential) String() string { return "credential(redacted)" }

// GoString redacts %#v as well.
func (Credential) GoString() string { return "device.Credential{redacted}" }

// CredentialSource resolves a named credential at runtime. The env provider
// below is the pre-S41 default; S41 (secrets integration) plugs Vault /
// CyberArk / cloud KMS into this same seam without touching callers.
type CredentialSource interface {
	Resolve(name string) (Credential, error)
}

// EnvCredentials resolves credentials from the environment:
//
//	PROBECTL_DEVICE_CRED_<NAME>_COMMUNITY
//	PROBECTL_DEVICE_CRED_<NAME>_USERNAME
//	PROBECTL_DEVICE_CRED_<NAME>_AUTH_PROTO / _AUTH_PASS
//	PROBECTL_DEVICE_CRED_<NAME>_PRIV_PROTO / _PRIV_PASS
//	PROBECTL_DEVICE_CRED_<NAME>_PASSWORD
//
// <NAME> is the upper-cased credential name with '-' and '.' mapped to '_'.
type EnvCredentials struct {
	getenv func(string) string
}

// NewEnvCredentials builds the env-backed source; getenv defaults to os.Getenv
// (the seam keeps tests hermetic).
func NewEnvCredentials(getenv func(string) string) *EnvCredentials {
	if getenv == nil {
		getenv = os.Getenv
	}
	return &EnvCredentials{getenv: getenv}
}

// Resolve returns the named credential. A name with no environment material at
// all is an error (a typo'd reference must fail loudly, not poll
// unauthenticated).
func (e *EnvCredentials) Resolve(name string) (Credential, error) {
	key := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToUpper(name))
	pfx := "PROBECTL_DEVICE_CRED_" + key + "_"
	c := Credential{
		Community: e.getenv(pfx + "COMMUNITY"),
		Username:  e.getenv(pfx + "USERNAME"),
		AuthProto: strings.ToLower(e.getenv(pfx + "AUTH_PROTO")),
		AuthPass:  e.getenv(pfx + "AUTH_PASS"),
		PrivProto: strings.ToLower(e.getenv(pfx + "PRIV_PROTO")),
		PrivPass:  e.getenv(pfx + "PRIV_PASS"),
		Password:  e.getenv(pfx + "PASSWORD"),
	}
	if c == (Credential{}) {
		return Credential{}, fmt.Errorf("device: credential %q not found (set %s* env vars, or wire a secrets backend — S41)", name, pfx)
	}
	return c, nil
}
