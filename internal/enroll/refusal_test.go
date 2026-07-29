// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"errors"
	"strings"
	"testing"
)

func TestRefusalTenantPreservesScopeWithoutLeakingIt(t *testing.T) {
	const tenantID = "122917df-b981-4034-86ae-4c430e192035"
	err := refuseTenant(tenantID, ErrInvalidProof)

	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("typed refusal lost its cause: %v", err)
	}
	if got, ok := RefusalTenant(err); !ok || got != tenantID {
		t.Fatalf("RefusalTenant = %q, %v; want %q, true", got, ok, tenantID)
	}
	if strings.Contains(err.Error(), tenantID) {
		t.Fatalf("tenant leaked into refusal error: %q", err)
	}
	if got, ok := RefusalTenant(ErrInvalidToken); ok || got != "" {
		t.Fatalf("unresolved token refusal gained tenant scope: %q, %v", got, ok)
	}
}
