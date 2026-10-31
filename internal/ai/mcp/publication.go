// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"maps"

	"github.com/ctlplne/probectl/internal/auth"
)

type publicationContextKey struct{}
type publicationGuard func(context.Context) error

func principalSnapshot(p *auth.Principal) *auth.Principal {
	return auth.ClonePrincipal(p)
}

func withPublicationGuard(ctx context.Context, guard publicationGuard) context.Context {
	return context.WithValue(ctx, publicationContextKey{}, guard)
}

func guardPublication(ctx context.Context) error {
	if guard, ok := ctx.Value(publicationContextKey{}).(publicationGuard); ok {
		return guard(ctx)
	}
	return ctx.Err()
}

func publicationPolicySnapshot(ctx context.Context, policies []auth.Policy) (map[string]bool, error) {
	if _, present := ctx.Value(publicationContextKey{}).(publicationGuard); !present {
		return nil, nil
	}
	return policyAuthoritySet(policies)
}

func policyAuthoritySet(policies []auth.Policy) (map[string]bool, error) {
	return auth.EnabledPolicyAuthoritySet(policies)
}

func (s *Server) guardToolPublication(ctx context.Context, p *auth.Principal, initialPolicies map[string]bool) error {
	if err := guardPublication(ctx); err != nil {
		return err
	}
	if initialPolicies == nil {
		return nil
	}
	policies, err := s.loadPolicies(ctx, p.TenantID)
	if err != nil {
		return ErrForbidden
	}
	current, err := policyAuthoritySet(policies)
	if err != nil || !maps.Equal(initialPolicies, current) {
		return ErrForbidden
	}
	return ctx.Err()
}

// Compare authority rather than display fields. Resource grants are sets, so
// database row ordering or duplicate grants cannot cause a spurious refusal.
func sameAuthority(a, b *auth.Principal) bool {
	return auth.SamePrincipalAuthority(a, b)
}
