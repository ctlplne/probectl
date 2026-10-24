// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type policyStoreSpy struct {
	stored Policy
	sets   int
}

func (s *policyStoreSpy) TenantPolicy(context.Context, string) (Policy, bool, error) {
	return s.stored, true, nil
}

func (s *policyStoreSpy) SetTenantPolicy(_ context.Context, _ string, pol Policy, _ string, _ func(context.Context, tenancy.Scope) error) error {
	s.sets++
	s.stored = pol
	return nil
}

// TestGatePolicyWritesDegradesClosedOnAReadOnlyLicense: once the license is
// read-only, a tenant governance edit is refused before it reaches the store —
// except withdrawing the remote-AI egress consent with nothing else changed,
// which stops telemetry leaving and must never be blocked. Before this gate the
// tenant /v1 surface was attached without the write capability that keys and
// remediation already honor, so every edit kept landing after expiry.
func TestGatePolicyWritesDegradesClosedOnAReadOnlyLicense(t *testing.T) {
	base := Policy{RedactFrom: ClassConfidential, RedactExport: true,
		Overrides: map[Category]Class{CatWorkload: ClassPII}}
	consented := base
	consented.AIRemoteEgress = true
	withdrawn := base // the same policy with the consent off
	loosened := base
	loosened.RedactExport = false

	for _, tc := range []struct {
		name     string
		writable bool
		prior    Policy
		next     Policy
		allowed  bool
	}{
		{"active license: any edit", true, withdrawn, loosened, true},
		{"read-only: withdraw consent and nothing else", false, consented, withdrawn, true},
		{"read-only: withdraw consent and loosen redaction", false, consented, loosened, false},
		{"read-only: grant consent", false, withdrawn, consented, false},
		{"read-only: unchanged consent, other edit", false, withdrawn, loosened, false},
		{"read-only: rewrite the same policy", false, withdrawn, withdrawn, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &policyStoreSpy{stored: tc.prior}
			gate := GatePolicyWrites(spy, func() bool { return tc.writable })
			err := gate.SetTenantPolicy(context.Background(), "t1", tc.next, "admin", func(context.Context, tenancy.Scope) error { return nil })
			if tc.allowed {
				if err != nil || spy.sets != 1 {
					t.Fatalf("allowed edit: err=%v sets=%d, want it to reach the store", err, spy.sets)
				}
				return
			}
			if !errors.Is(err, license.ErrReadOnly) || spy.sets != 0 {
				t.Fatalf("refused edit: err=%v sets=%d, want license.ErrReadOnly before the store", err, spy.sets)
			}
		})
	}

	// Reads stay available on a read-only license.
	spy := &policyStoreSpy{stored: consented}
	got, _, err := GatePolicyWrites(spy, func() bool { return false }).TenantPolicy(context.Background(), "t1")
	if err != nil || !got.AIRemoteEgress {
		t.Fatalf("read-only read = %+v, %v; want the stored policy", got, err)
	}
	if GatePolicyWrites(nil, nil) != nil {
		t.Fatal("a nil store must stay nil so the surface stays hidden")
	}
}
