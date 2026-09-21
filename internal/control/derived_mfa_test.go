// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDerivedMFAAttributeCannotBeOverridden(t *testing.T) {
	tests := []struct {
		name           string
		mfaSatisfied   bool
		directoryMFA   string
		wantDerivedMFA string
	}{
		{
			name:           "directory cannot forge MFA",
			mfaSatisfied:   false,
			directoryMFA:   "true",
			wantDerivedMFA: "false",
		},
		{
			name:           "directory cannot downgrade MFA",
			mfaSatisfied:   true,
			directoryMFA:   "false",
			wantDerivedMFA: "true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := &auth.Principal{
				TenantID:     "00000000-0000-0000-0000-0000000000a1",
				UserID:       "00000000-0000-0000-0000-0000000000b1",
				MFASatisfied: tt.mfaSatisfied,
			}
			err := loadSubjectAttributesWith(
				context.Background(),
				principal,
				func(ctx context.Context, tenantID string, fn func(context.Context, tenancy.Scope) error) error {
					return fn(ctx, tenancy.Scope{Tenant: tenancy.ID(tenantID)})
				},
				func(context.Context, tenancy.Scope, string) (*store.User, error) {
					return &store.User{Attributes: map[string]string{
						"department": "network-operations",
						"mfa":        tt.directoryMFA,
					}}, nil
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := principal.Attributes["mfa"]; got != tt.wantDerivedMFA {
				t.Fatalf("derived mfa = %q, want %q (directory supplied %q)",
					got, tt.wantDerivedMFA, tt.directoryMFA)
			}
			if got := principal.Attributes["department"]; got != "network-operations" {
				t.Fatalf("ordinary directory attribute = %q, want preserved", got)
			}
		})
	}
}
