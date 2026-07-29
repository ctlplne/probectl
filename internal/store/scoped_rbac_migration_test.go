// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/migrations"
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
