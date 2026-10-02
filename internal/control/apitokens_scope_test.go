// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

// INV-03/RT-02: a scoped token exercises only its permission subset. The read
// enforcement runs at the authorization input — narrowPrincipalToScopes strips
// the write permissions from BOTH the flat map and the resource-scoped grants,
// so Principal.Has/HasAny (which route RBAC consults) can no longer satisfy a
// write route for a read-only token.
func TestNarrowPrincipalToScopes(t *testing.T) {
	base := func() *auth.Principal {
		return &auth.Principal{
			TenantID: "t", UserID: "u",
			Permissions: map[string]bool{
				"test.read": true, "test.write": true,
				"agent.read": true, "ir.investigate": true,
			},
			PermissionGrants: []auth.PermissionGrant{
				{Permission: "test.write", ScopeType: auth.ScopeTenant},
				{Permission: "test.read", ScopeType: auth.ScopeTenant},
				{Permission: "ir.investigate", ScopeType: auth.ScopeTenant},
			},
		}
	}

	t.Run("empty scopes keep full RBAC", func(t *testing.T) {
		p := narrowPrincipalToScopes(base(), nil)
		if !p.Has("test.write") || !p.Has("test.read") {
			t.Fatal("an unscoped token must keep the owner's full permissions")
		}
	})

	t.Run("read-only strips every write permission", func(t *testing.T) {
		p := narrowPrincipalToScopes(base(), []string{"read"})
		if p.Has("test.write") {
			t.Error("read-only token must not satisfy test.write (a write route)")
		}
		if p.Has("ir.investigate") {
			t.Error("read-only token must not satisfy ir.investigate (a privileged action)")
		}
		if !p.Has("test.read") || !p.Has("agent.read") {
			t.Error("read-only token must keep the read permissions")
		}
		// The resource-scoped grants are filtered too (HasAny consults them).
		if p.HasAny("test.write") {
			t.Error("read-only token must not retain a write grant")
		}
	})

	t.Run("explicit subset keeps only listed keys", func(t *testing.T) {
		p := narrowPrincipalToScopes(base(), []string{"agent.read"})
		if !p.Has("agent.read") {
			t.Error("explicitly-scoped permission must be kept")
		}
		if p.Has("test.read") || p.Has("test.write") {
			t.Error("a permission outside the explicit scope must be dropped")
		}
	})

	t.Run("original principal is not mutated", func(t *testing.T) {
		orig := base()
		_ = narrowPrincipalToScopes(orig, []string{"read"})
		if !orig.Has("test.write") {
			t.Error("narrowing must not mutate the caller's principal")
		}
	})
}

func TestIsReadPermission(t *testing.T) {
	read := []string{"test.read", "agent.read", "metrics.list", "topology.view"}
	write := []string{"test.write", "ir.investigate", "agent.write", "lifecycle.erase", "security.keys", "noaction", "remediation.approve"}
	for _, k := range read {
		if !isReadPermission(k) {
			t.Errorf("%q should be read-only", k)
		}
	}
	for _, k := range write {
		if isReadPermission(k) {
			t.Errorf("%q must not be classified read-only", k)
		}
	}
}
