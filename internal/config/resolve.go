package config

import (
	"context"
	"fmt"
)

// ResolveSecretRefs resolves every secret-bearing config field through the
// supplied resolver (S41, F31): values that are secret references
// (env:/vault:/cyberark:/aws:/azure:/gcp:) are replaced in memory with the
// resolved material at startup; plain values pass through unchanged. The
// resolve seam is satisfied by (*secrets.Resolver).Resolve.
//
// This is the EXPLICIT list of integration credentials the control plane
// accepts (extend it when a new secret-bearing key lands — and document the
// key in docs/configuration.md):
//
//	PROBECTL_OIDC_CLIENT_SECRET      → OIDCClientSecret
//	PROBECTL_CMDB_SECRET             → CMDBSecret
//	PROBECTL_AI_MODEL_TOKEN          → AIModelToken
//	PROBECTL_SIEM_TOKEN              → SIEMToken
//	PROBECTL_CHANGE_WEBHOOKS         → ChangeWebhooks[].Secret
//	PROBECTL_NOTIFY_CONNECTORS       → NotifyConnectors[].Secret
//	PROBECTL_NOTIFY_INBOUND          → NotifyInbound[].Secret
//
// Any resolution failure is returned (fail closed): the control plane must
// not start with a partially-resolved credential set. OTLP ingest tokens are
// NOT resolved — they are probectl-issued inbound tokens, not external-system
// credentials, and their list syntax (token=tenant,...) is incompatible with
// reference strings.
func (c *Config) ResolveSecretRefs(ctx context.Context, resolve func(context.Context, string) (string, error)) error {
	if resolve == nil {
		return fmt.Errorf("config: secret resolver is required")
	}
	fields := []struct {
		name string // env-style name for the error message; never the value
		p    *string
	}{
		{"PROBECTL_OIDC_CLIENT_SECRET", &c.OIDCClientSecret},
		{"PROBECTL_CMDB_SECRET", &c.CMDBSecret},
		{"PROBECTL_AI_MODEL_TOKEN", &c.AIModelToken},
		{"PROBECTL_SIEM_TOKEN", &c.SIEMToken},
	}
	for i := range c.NotifyConnectors {
		fields = append(fields, struct {
			name string
			p    *string
		}{fmt.Sprintf("PROBECTL_NOTIFY_CONNECTORS[%d]", i), &c.NotifyConnectors[i].Secret})
	}
	for _, f := range fields {
		if *f.p == "" {
			continue
		}
		v, err := resolve(ctx, *f.p)
		if err != nil {
			// The resolver's error is already redacted (reference fragment
			// hidden, no secret material) — safe to wrap with the field name.
			return fmt.Errorf("config: %s: %w", f.name, err)
		}
		*f.p = v
	}
	// Map-valued credential sets (map values aren't addressable).
	for id, wh := range c.ChangeWebhooks {
		if wh.Secret == "" {
			continue
		}
		v, err := resolve(ctx, wh.Secret)
		if err != nil {
			return fmt.Errorf("config: PROBECTL_CHANGE_WEBHOOKS[%s]: %w", id, err)
		}
		wh.Secret = v
		c.ChangeWebhooks[id] = wh
	}
	for id, in := range c.NotifyInbound {
		if in.Secret == "" {
			continue
		}
		v, err := resolve(ctx, in.Secret)
		if err != nil {
			return fmt.Errorf("config: PROBECTL_NOTIFY_INBOUND[%s]: %w", id, err)
		}
		in.Secret = v
		c.NotifyInbound[id] = in
	}
	return nil
}
