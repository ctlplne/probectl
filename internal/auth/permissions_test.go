// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScopedRBACPrincipalRequiresMatchingLineage(t *testing.T) {
	p := &Principal{
		Permissions: map[string]bool{"tenant.read": true},
		PermissionGrants: []PermissionGrant{
			{Permission: "org.read", ScopeType: ScopeOrganization, ScopeID: "org-a"},
			{Permission: "org.write", ScopeType: ScopeTeam, ScopeID: "team-a"},
			{Permission: "test.read", ScopeType: ScopeProject, ScopeID: "project-a"},
			{Permission: "invalid", ScopeType: "cluster", ScopeID: "cluster-a"},
		},
	}

	if !p.Has("tenant.read") {
		t.Fatal("legacy tenant-wide permission must remain tenant-wide")
	}
	if p.Has("org.read") || p.Has("org.write") || p.Has("test.read") {
		t.Fatal("Has must never promote a resource-scoped grant to tenant-wide")
	}
	if !p.HasAny("org.read") || !p.HasAny("org.write") || !p.HasAny("test.read") {
		t.Fatal("HasAny must report valid scoped grants")
	}
	if p.HasAny("invalid") {
		t.Fatal("unknown scope type must fail closed")
	}

	if !p.HasAt("org.read", ResourceLineage{OrganizationID: "org-a"}) ||
		!p.HasAt("org.read", ResourceLineage{OrganizationID: "org-a", TeamID: "team-a", ProjectID: "project-a"}) {
		t.Fatal("organization grant must authorize that organization and descendants")
	}
	if p.HasAt("org.read", ResourceLineage{OrganizationID: "org-b", TeamID: "team-a"}) {
		t.Fatal("organization grant must not authorize a sibling organization")
	}
	if !p.HasAt("org.write", ResourceLineage{OrganizationID: "org-a", TeamID: "team-a", ProjectID: "project-a"}) {
		t.Fatal("team grant must authorize that team and descendants")
	}
	if p.HasAt("org.write", ResourceLineage{OrganizationID: "org-a", TeamID: "team-b"}) {
		t.Fatal("team grant must not authorize a sibling team")
	}
	if !p.HasAt("test.read", ResourceLineage{OrganizationID: "org-a", TeamID: "team-a", ProjectID: "project-a"}) {
		t.Fatal("project grant must authorize only its project")
	}
	if p.HasAt("test.read", ResourceLineage{OrganizationID: "org-a", TeamID: "team-a", ProjectID: "project-b"}) {
		t.Fatal("project grant must not authorize a sibling project")
	}
}

func TestScopedRBACFingerprintIncludesScope(t *testing.T) {
	orgA := []PermissionGrant{{Permission: "org.write", ScopeType: ScopeOrganization, ScopeID: "org-a"}}
	orgB := []PermissionGrant{{Permission: "org.write", ScopeType: ScopeOrganization, ScopeID: "org-b"}}
	if bytes.Equal(PermissionGrantFingerprint(orgA), PermissionGrantFingerprint(orgB)) {
		t.Fatal("changing only scope id must rotate the authorization fingerprint")
	}
	reordered := []PermissionGrant{
		{Permission: "org.read", ScopeType: ScopeTeam, ScopeID: "team-a"},
		{Permission: "org.write", ScopeType: ScopeOrganization, ScopeID: "org-a"},
	}
	reversed := []PermissionGrant{reordered[1], reordered[0]}
	if !bytes.Equal(PermissionGrantFingerprint(reordered), PermissionGrantFingerprint(reversed)) {
		t.Fatal("database row order must not change the authorization fingerprint")
	}
}

type mutableGrantLoader struct {
	grants []PermissionGrant
}

func (m *mutableGrantLoader) ForUser(context.Context, string, string) ([]PermissionGrant, error) {
	return append([]PermissionGrant(nil), m.grants...), nil
}

func TestScopedRBACScopeChangeRotatesSession(t *testing.T) {
	store := newFakeStore()
	manager := NewManager(store, time.Hour, false, nil)
	loader := &mutableGrantLoader{grants: []PermissionGrant{{
		Permission: "org.write", ScopeType: ScopeOrganization, ScopeID: "org-a",
	}}}
	token, err := manager.Issue(context.Background(), Session{
		TenantID:          "tenant-a",
		UserID:            "user-a",
		AuthorizationHash: PermissionGrantFingerprint(loader.grants),
	})
	if err != nil {
		t.Fatal(err)
	}
	loader.grants[0].ScopeID = "org-b"

	req := httptest.NewRequest(http.MethodGet, "/v1/hierarchy", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	principal, replacement, err := NewAuthenticator(manager, loader).ResolveAndRotate(req)
	if err != nil {
		t.Fatal(err)
	}
	if replacement == "" {
		t.Fatal("scope-only authorization change must rotate the opaque session")
	}
	if principal.HasAt("org.write", ResourceLineage{OrganizationID: "org-a"}) ||
		!principal.HasAt("org.write", ResourceLineage{OrganizationID: "org-b"}) {
		t.Fatalf("rotated principal retained stale scope: %+v", principal.PermissionGrants)
	}
}
