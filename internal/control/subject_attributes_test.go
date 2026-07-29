// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type subjectAttributeSessionStore struct {
	session *auth.Session
}

func (s *subjectAttributeSessionStore) Create(_ context.Context, _ []byte, session auth.Session) error {
	clone := session
	s.session = &clone
	return nil
}

func (s *subjectAttributeSessionStore) LookupByHash(context.Context, []byte, time.Duration) (*auth.Session, error) {
	if s.session == nil {
		return nil, nil
	}
	clone := *s.session
	return &clone, nil
}

func (s *subjectAttributeSessionStore) RotateByHash(_ context.Context, _, _ []byte, session auth.Session) (bool, error) {
	clone := session
	s.session = &clone
	return true, nil
}

func (s *subjectAttributeSessionStore) DeleteByHash(context.Context, []byte) error {
	s.session = nil
	return nil
}

type subjectAttributePermissions struct {
	keys []string
}

func (p subjectAttributePermissions) ForUser(context.Context, string, string) ([]string, error) {
	return append([]string(nil), p.keys...), nil
}

func TestSubjectAttributeLoadFailureFailsClosed(t *testing.T) {
	pool := closedSubjectAttributePool(t)
	defer pool.Close()

	var logs bytes.Buffer
	keys := []string{permTestRead}
	sessionStore := &subjectAttributeSessionStore{}
	sessionManager := auth.NewManager(sessionStore, time.Hour, false, nil)
	token, err := sessionManager.Issue(context.Background(), auth.Session{
		TenantID:          "00000000-0000-0000-0000-0000000000a1",
		UserID:            "00000000-0000-0000-0000-0000000000b1",
		AuthorizationHash: auth.PermissionFingerprint(keys),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		cfg:      &config.Config{AuthMode: "session"},
		log:      logging.New(&logs, "warn", "json"),
		pool:     pool,
		sessions: sessionManager,
		authn:    auth.NewAuthenticator(sessionManager, subjectAttributePermissions{keys: keys}),
	}

	userQueryErr := errors.New("fixture user query failure")
	attributeFailures := []struct {
		name string
		load func(context.Context, *auth.Principal) error
	}{
		{name: "tenant_scope", load: srv.loadSubjectAttributes},
		{
			name: "user_query",
			load: func(ctx context.Context, p *auth.Principal) error {
				return loadSubjectAttributesWith(ctx, p,
					func(ctx context.Context, tenantID string, fn func(context.Context, tenancy.Scope) error) error {
						return fn(ctx, tenancy.Scope{Tenant: tenancy.ID(tenantID)})
					},
					func(context.Context, tenancy.Scope, string) (*store.User, error) {
						return nil, userQueryErr
					})
			},
		},
	}

	tests := []struct {
		name            string
		request         func() *http.Request
		resolveBearer   func(*http.Request, string) (*auth.Principal, error)
		wantBearerCalls int
	}{
		{
			name: "bearer",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
				req.Header.Set("Authorization", "Bearer fixture-bearer-secret")
				return req
			},
			resolveBearer: func(_ *http.Request, token string) (*auth.Principal, error) {
				if token != "fixture-bearer-secret" {
					t.Fatalf("bearer resolver received %q", token)
				}
				return &auth.Principal{
					TenantID:    "00000000-0000-0000-0000-0000000000a1",
					UserID:      "00000000-0000-0000-0000-0000000000b1",
					Permissions: map[string]bool{permTestRead: true},
				}, nil
			},
			wantBearerCalls: 1,
		},
		{
			name: "session",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
				req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
				return req
			},
			resolveBearer: func(*http.Request, string) (*auth.Principal, error) {
				t.Fatal("session authentication called the bearer resolver")
				return nil, nil
			},
		},
	}
	for _, failure := range attributeFailures {
		t.Run(failure.name, func(t *testing.T) {
			incomplete := &auth.Principal{
				TenantID:    "00000000-0000-0000-0000-0000000000a1",
				UserID:      "00000000-0000-0000-0000-0000000000b1",
				Permissions: map[string]bool{permTestRead: true},
			}
			if err := failure.load(context.Background(), incomplete); err == nil {
				t.Fatal("subject attribute loader hid the tenant-scoped user lookup failure")
			}
			if incomplete.Attributes != nil {
				t.Fatalf("failed attribute load attached a partial attribute set: %v", incomplete.Attributes)
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					bearerCalls := 0
					request := tt.request()
					resolved := srv.resolvePrincipalSessionWith(nil, request,
						func(r *http.Request, token string) (*auth.Principal, error) {
							bearerCalls++
							return tt.resolveBearer(r, token)
						},
						failure.load)
					if bearerCalls != tt.wantBearerCalls {
						t.Fatalf("bearer resolver calls = %d, want %d", bearerCalls, tt.wantBearerCalls)
					}

					ran := false
					protected := srv.requirePermission(permTestRead, func(http.ResponseWriter, *http.Request) error {
						ran = true
						return nil
					})
					if resolved != nil {
						request = request.WithContext(auth.WithPrincipal(request.Context(), resolved))
					}
					err := protected(httptest.NewRecorder(), request)
					domainErr, ok := apierror.As(err)
					if !ok || domainErr.Kind != apierror.KindUnauthorized {
						t.Fatalf("incomplete %s principal authorization = %v, want unauthorized", tt.name, err)
					}
					if resolved != nil {
						t.Errorf("subject attribute lookup failure returned an authenticated principal: %+v", resolved)
					}
					if ran {
						t.Fatalf("RBAC-protected handler ran for incomplete %s principal", tt.name)
					}
				})
			}
		})
	}

	if got := logs.String(); strings.Contains(got, "fixture-bearer-secret") {
		t.Fatalf("authentication failure log contained bearer material: %s", got)
	}
}

func closedSubjectAttributePool(t *testing.T) *pgxpool.Pool {
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
	return pool
}
