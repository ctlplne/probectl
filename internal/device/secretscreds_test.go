package device

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestSecretsCredentialsResolvesRefsAndLiterals(t *testing.T) {
	env := map[string]string{
		"PROBECTL_DEVICE_CRED_CORE_SW_USERNAME":   "monitor",                   // literal
		"PROBECTL_DEVICE_CRED_CORE_SW_AUTH_PASS":  "vault:kv/netops/snmp#auth", // ref
		"PROBECTL_DEVICE_CRED_CORE_SW_PRIV_PASS":  "vault:kv/netops/snmp#priv", // ref
		"PROBECTL_DEVICE_CRED_CORE_SW_AUTH_PROTO": "SHA256",
		"PROBECTL_DEVICE_CRED_CORE_SW_PRIV_PROTO": "AES",
	}
	var resolved []string
	resolve := func(_ context.Context, raw string) (string, error) {
		resolved = append(resolved, raw)
		switch raw {
		case "vault:kv/netops/snmp#auth":
			return "auth-material", nil
		case "vault:kv/netops/snmp#priv":
			return "priv-material", nil
		}
		return raw, nil
	}
	src, err := NewSecretsCredentials(func(k string) string { return env[k] }, resolve)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := src.Resolve("core-sw")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "monitor" || cred.AuthPass != "auth-material" || cred.PrivPass != "priv-material" {
		t.Fatalf("cred = %s/%s/%s", cred.Username, cred.AuthPass, cred.PrivPass)
	}
	if cred.AuthProto != "sha256" || cred.PrivProto != "aes" {
		t.Fatalf("protos = %s/%s", cred.AuthProto, cred.PrivProto)
	}
	// Both refs went through the resolver (lease behavior lives there).
	if len(resolved) != 5 { // every non-empty field passes through
		t.Fatalf("resolver saw %d values, want 5", len(resolved))
	}
}

func TestSecretsCredentialsFailClosed(t *testing.T) {
	env := map[string]string{"PROBECTL_DEVICE_CRED_EDGE_COMMUNITY": "vault:kv/x#community"}
	resolve := func(context.Context, string) (string, error) {
		return "", fmt.Errorf("secrets: resolve vault:kv/x#…: backend unavailable")
	}
	src, err := NewSecretsCredentials(func(k string) string { return env[k] }, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Resolve("edge"); err == nil {
		t.Fatal("backend failure must fail the credential (fail closed)")
	} else if !strings.Contains(err.Error(), "COMMUNITY") {
		t.Fatalf("error should name the field: %v", err)
	}

	// Unknown credential name still fails loudly.
	if _, err := src.Resolve("typo"); err == nil {
		t.Fatal("missing credential resolved")
	}

	// A nil resolver is a constructor error, not a silent env fallback.
	if _, err := NewSecretsCredentials(nil, nil); err == nil {
		t.Fatal("nil resolver accepted")
	}
}
