// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
)

func TestABACColdLoadFailureFailsClosed(t *testing.T) {
	s := &Server{abac: newClosedABACCache(t)}
	ran := false
	protected := s.requirePermission("test.read", func(http.ResponseWriter, *http.Request) error {
		ran = true
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
		TenantID:    "t-acme",
		Permissions: map[string]bool{"test.read": true},
	}))

	err := protected(httptest.NewRecorder(), req)
	domainErr, ok := apierror.As(err)
	if !ok || domainErr.Kind != apierror.KindUnavailable {
		t.Fatalf("cold ABAC load failure = %v, want unavailable", err)
	}
	if ran {
		t.Fatal("protected handler ran without a safely loaded ABAC policy set")
	}
}

func TestABACExpiredCacheRefreshFailureFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		policies []auth.Policy
	}{
		{
			name:     "tenant A empty policy set",
			tenantID: "t-acme-a",
		},
		{
			name:     "tenant B stale allow",
			tenantID: "t-acme-b",
			policies: []auth.Policy{{
				ID:         "allow-read",
				Effect:     auth.PolicyAllow,
				Permission: "test.read",
				Enabled:    true,
			}},
		},
		{
			name:     "tenant C stale deny",
			tenantID: "t-acme-c",
			policies: []auth.Policy{{
				ID:         "deny-read",
				Effect:     auth.PolicyDeny,
				Permission: "test.read",
				Enabled:    true,
			}},
		},
	}

	cache := newClosedABACCache(t)
	for _, tt := range tests {
		cache.data[tt.tenantID] = abacEntry{
			expiry:   time.Now().Add(-time.Minute),
			policies: tt.policies,
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{abac: cache}
			ran := false
			protected := s.requirePermission("test.read", func(http.ResponseWriter, *http.Request) error {
				ran = true
				return nil
			})
			req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
			req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
				TenantID:    tt.tenantID,
				Permissions: map[string]bool{"test.read": true},
			}))

			err := protected(httptest.NewRecorder(), req)
			domainErr, ok := apierror.As(err)
			if !ok || domainErr.Kind != apierror.KindUnavailable {
				t.Fatalf("expired ABAC refresh failure = %v, want unavailable", err)
			}
			if ran {
				t.Fatal("protected handler ran with an expired ABAC policy set")
			}
		})
	}
}

func TestABACUnexpiredPolicyStillDeniesWithinTTL(t *testing.T) {
	cache := newClosedABACCache(t)
	cache.data["t-acme"] = abacEntry{
		expiry: time.Now().Add(time.Minute),
		policies: []auth.Policy{{
			ID:         "deny-read",
			Effect:     auth.PolicyDeny,
			Permission: "test.read",
			Enabled:    true,
		}},
	}
	s := &Server{abac: cache}
	ran := false
	protected := s.requirePermission("test.read", func(http.ResponseWriter, *http.Request) error {
		ran = true
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), &auth.Principal{
		TenantID:    "t-acme",
		Permissions: map[string]bool{"test.read": true},
	}))

	err := protected(httptest.NewRecorder(), req)
	domainErr, ok := apierror.As(err)
	if !ok || domainErr.Kind != apierror.KindForbidden {
		t.Fatalf("unexpired deny policy decision = %v, want forbidden", err)
	}
	if ran {
		t.Fatal("protected handler ran despite an unexpired deny policy")
	}
}

func newClosedABACCache(t *testing.T) *abacCache {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://probectl@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	return newABACCache(pool)
}
