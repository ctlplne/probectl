// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browsercanary

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/browser"
	"github.com/ctlplne/probectl/internal/secrets"
)

// APITransactionConfig holds deployment-owned settings. Signed tests select
// aliases. The agent alone maps a tenant, alias and TLS origin to a backend.
type APITransactionConfig struct {
	MaxBytes int                `yaml:"max_bytes,omitempty"`
	CAFile   string             `yaml:"ca_file,omitempty"`
	Secrets  []APISecretBinding `yaml:"secrets,omitempty"`
}

type APISecretBinding struct {
	TenantID string `yaml:"tenant_id"`
	Alias    string `yaml:"alias"`
	Origin   string `yaml:"origin"`
	Ref      string `yaml:"ref"`
}

type apiCredentialKey struct{ tenant, alias, origin string }

type apiCredentialBindings struct {
	refs     map[apiCredentialKey]string
	resolver *secrets.Resolver
}

func buildAPICredentialBindings(cfg APITransactionConfig) (*apiCredentialBindings, error) {
	if cfg.MaxBytes < 0 {
		return nil, errors.New("browser: API transaction byte budget cannot be negative")
	}
	if len(cfg.Secrets) == 0 {
		return nil, nil
	}
	refs := make(map[apiCredentialKey]string, len(cfg.Secrets))
	for i, binding := range cfg.Secrets {
		tenant, tenantErr := uuid.Parse(binding.TenantID)
		origin, originErr := browser.CanonicalAPISecretOrigin(binding.Origin)
		if tenantErr != nil || tenant == uuid.Nil || tenant.String() != binding.TenantID || originErr != nil ||
			!browser.ValidAPISecretAlias(binding.Alias) || !secrets.IsRef(binding.Ref) {
			return nil, fmt.Errorf("browser: invalid API credential binding %d", i+1)
		}
		if _, err := secrets.Parse(binding.Ref); err != nil {
			return nil, fmt.Errorf("browser: invalid API credential reference in binding %d", i+1)
		}
		key := apiCredentialKey{tenant: binding.TenantID, alias: binding.Alias, origin: origin}
		if _, present := refs[key]; present {
			return nil, fmt.Errorf("browser: duplicate API credential binding %d", i+1)
		}
		refs[key] = binding.Ref
	}
	resolver, err := secrets.FromEnv(0)
	if err != nil {
		return nil, errors.New("browser: could not configure API credential backends")
	}
	return &apiCredentialBindings{refs: refs, resolver: resolver}, nil
}

func (b *apiCredentialBindings) resolve(ctx context.Context, tenant, alias, origin string) ([]byte, func(), error) {
	if b != nil && tenant != "" && b.resolver != nil {
		if ref, ok := b.refs[apiCredentialKey{tenant: tenant, alias: alias, origin: origin}]; ok {
			// Read at use time so disabling the credential takes effect on the
			// next request. The caller clears the returned bytes after copying.
			return b.resolver.ResolveBytesUncached(ctx, ref)
		}
	}
	return nil, nil, errors.New("browser: no credential is configured for this tenant and origin")
}
