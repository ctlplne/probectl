// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
)

type mcpLifecycleSource struct {
	seen []string
}

func (s *mcpLifecycleSource) TenantStatus(_ context.Context, tenant string) (string, error) {
	s.seen = append(s.seen, tenant)
	if tenant == "unreadable" {
		return "", errors.New("private tenant database diagnostic")
	}
	return "active", nil
}

func TestMCPPolicyFailsClosedOnUnknownLifecycle(t *testing.T) {
	source := &mcpLifecycleSource{}
	authn := mcpAuthenticator{status: source}
	err := authn.checkTenantPolicy(t.Context(), "unreadable")
	var domain *apierror.Error
	if !errors.As(err, &domain) || domain.Kind != apierror.KindUnavailable {
		t.Fatalf("unknown tenant lifecycle must refuse with retryable unavailable, got %v", err)
	}
	if strings.Contains(err.Error(), "private tenant") {
		t.Fatal("lifecycle refusal copied the source diagnostic")
	}
	if err := authn.checkTenantPolicy(t.Context(), "healthy-sibling"); err != nil {
		t.Fatal("one tenant's failed lookup refused a healthy sibling", err)
	}
	if len(source.seen) != 2 || source.seen[0] != "unreadable" || source.seen[1] != "healthy-sibling" {
		t.Fatal("lifecycle lookup used another tenant")
	}
}

func TestMCPPolicyKnownLifecycleAndMFA(t *testing.T) {
	for _, status := range []string{"active", "suspended", "offboarding", "deleted"} {
		for _, mfa := range []bool{false, true} {
			err := (mcpAuthenticator{status: fixedTenantStatus(status), requireMFA: mfa}).checkTenantPolicy(t.Context(), "owned")
			refused := status != "active" || mfa
			if (err != nil) != refused || (refused && !errors.Is(err, mcp.ErrForbidden)) {
				t.Fatalf("status=%s mfa=%v: refusal=%v", status, mfa, err)
			}
		}
	}
}
