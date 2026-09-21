// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/migrations"
)

func TestScopedRBACTenantScopeMigrationIsOnline(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0074_role_binding_scope_shape.sql")
	if err != nil {
		t.Fatalf("read scoped RBAC migration: %v", err)
	}
	sql := strings.ToLower(string(raw))
	for _, want := range []string{
		"scope_type = 'tenant' and scope_id is null",
		"scope_type <> 'tenant' and scope_id is not null",
		"not valid",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("scope shape migration missing %q", want)
		}
	}
	if strings.Contains(sql, "validate constraint") {
		t.Fatal("the additive migration must not synchronously validate the existing table")
	}
}
