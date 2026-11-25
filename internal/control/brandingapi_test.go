// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/branding"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestBrandingEndpointIsDeploymentScopedAndProbectlBranded(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.cfg.ThemeOverrides = map[string]string{
		"--primary":            "28 85% 30%",
		"--primary-foreground": "0 0% 100%",
	}

	read := func(host, tenant string) (branding.Branding, http.Header) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/branding", nil)
		req.Host = host
		req = req.WithContext(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)))
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("branding %s: %d", host, rr.Code)
		}
		var got branding.Branding
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got, rr.Header()
	}

	a, headers := read("tenant-a.example", "tenant-a")
	b, _ := read("tenant-b.example", "tenant-b")
	if a.ProductName != "probectl" || b.ProductName != "probectl" {
		t.Fatalf("product identity changed: A=%+v B=%+v", a, b)
	}
	if a.TokenOverrides["--primary"] != "28 85% 30%" || b.TokenOverrides["--primary"] != "28 85% 30%" {
		t.Fatalf("deployment overrides differ by host: A=%+v B=%+v", a, b)
	}
	if vary := headers.Get("Vary"); vary != "" {
		t.Fatalf("deployment response must not vary by host: %q", vary)
	}
	if cache := headers.Get("Cache-Control"); cache != "public, max-age=60" {
		t.Fatalf("cache control = %q", cache)
	}
}

type fixtureBrandResolver struct{}

const mappedBrandTenant = "00000000-0000-4000-8000-000000000021"
const siblingBrandTenant = "00000000-0000-4000-8000-000000000022"

func (fixtureBrandResolver) ForTenant(ctx context.Context, tenantID string) (branding.Branding, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant.String() != tenantID {
		return branding.Branding{}, tenancy.ErrNoTenant
	}
	out := branding.Default()
	switch tenantID {
	case mappedBrandTenant:
		out.Customer = &branding.CustomerIdentity{Name: "Northstar"}
	case siblingBrandTenant:
		out.Customer = &branding.CustomerIdentity{Name: "Riverside"}
	}
	return out, nil
}

func (fixtureBrandResolver) TenantForHost(_ context.Context, host string) (string, error) {
	switch host {
	case "northstar.example":
		return mappedBrandTenant, nil
	case "riverside.example":
		return siblingBrandTenant, nil
	case "unavailable.example":
		return "", errors.New("fixture registry unavailable")
	default:
		return "", nil
	}
}

func (fixtureBrandResolver) HostForTenant(_ context.Context, tenant string) (string, error) {
	switch tenant {
	case mappedBrandTenant:
		return "northstar.example", nil
	case siblingBrandTenant:
		return "riverside.example", nil
	default:
		return "", nil
	}
}

func (f fixtureBrandResolver) ForHost(ctx context.Context, host string) (string, branding.Branding, error) {
	tenant, err := f.TenantForHost(ctx, host)
	if tenant == "" || err != nil {
		return tenant, branding.Default(), err
	}
	out, err := f.ForTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), tenant)
	out.CustomerDomain = true
	return tenant, out, err
}

type unavailableBrandSessionStore struct{ subjectAttributeSessionStore }

func (*unavailableBrandSessionStore) LookupByHash(context.Context, []byte, time.Duration) (*auth.Session, error) {
	return nil, errors.New("fixture session lookup unavailable")
}

type movableBrandHost struct {
	fixtureBrandResolver
	tenant string
}

func (f *movableBrandHost) TenantForHost(ctx context.Context, host string) (string, error) {
	if host == "northstar.example" {
		return f.tenant, nil
	}
	return f.fixtureBrandResolver.TenantForHost(ctx, host)
}

type brandExchangeProvider struct {
	nonce    string
	exchange func()
}

func (p *brandExchangeProvider) AuthCodeURL(_, nonce, _ string) string {
	p.nonce = nonce
	return "https://idp.northstar.example/authorize"
}

func (p *brandExchangeProvider) Exchange(context.Context, string, string) (*auth.Identity, error) {
	p.exchange()
	return &auth.Identity{Email: "user@northstar.example", Nonce: p.nonce}, nil
}

func testBrandHostChangeDuringExchange(t *testing.T) {
	for _, tc := range []struct{ name, nextOwner string }{
		{"another tenant", siblingBrandTenant},
		{"removed assignment", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &movableBrandHost{tenant: mappedBrandTenant}
			srv := testServer(fakePinger{}).WithCustomerBranding(resolver)
			srv.cfg.AuthMode = "sso"
			factory := newOIDCFactory(srv.cfg, nil)
			factory.idps = &unitTenantIDPSource{items: map[string]*store.TenantIDP{
				mappedBrandTenant: {
					Enabled: true, Issuer: "https://idp.northstar.example", ClientID: "northstar", ClientSecret: "fixture",
					RedirectURL: "https://northstar.example/auth/callback",
				},
			}}
			exchanges := 0
			factory.build = func(context.Context, auth.OIDCConfig) (auth.Provider, error) {
				return &brandExchangeProvider{exchange: func() {
					exchanges++
					resolver.tenant = tc.nextOwner
				}}, nil
			}
			srv.setSSOProviderFactory(factory)
			const host = "https://northstar.example"
			login := httptest.NewRecorder()
			srv.Handler().ServeHTTP(login, httptest.NewRequest(http.MethodGet, host+"/auth/login", nil))
			if login.Code != http.StatusFound {
				t.Fatalf("customer login returned %d: %s", login.Code, login.Body.String())
			}
			callback := httptest.NewRequest(http.MethodGet, host+"/auth/callback?code=fixture", nil)
			query := callback.URL.Query()
			for _, cookie := range login.Result().Cookies() {
				callback.AddCookie(cookie)
				if cookie.Name == oauthStateCookie {
					query.Set("state", cookie.Value)
				}
			}
			callback.URL.RawQuery = query.Encode()
			result := httptest.NewRecorder()
			srv.Handler().ServeHTTP(result, callback)
			if exchanges != 1 || result.Code != http.StatusUnauthorized || result.Header().Get("Location") != "" {
				t.Fatalf("callback did not refuse the changed host after exchange: %d exchanges, %d, %s", exchanges, result.Code, result.Body.String())
			}
			for _, cookie := range result.Result().Cookies() {
				if cookie.Name == auth.SessionCookie {
					t.Fatal("callback issued a session after its host assignment changed")
				}
			}
		})
	}
}

func TestCustomerBrandingEndpointUsesTheActualHostAndRefusesTenantMismatch(t *testing.T) {
	t.Run("host changes during identity exchange", testBrandHostChangeDuringExchange)
	srv := testServer(fakePinger{}).WithCustomerBranding(fixtureBrandResolver{})
	srv.cfg.AuthMode = "sso"
	for _, tc := range []struct{ host, forwarded, name string }{
		{"northstar.example", "foreign.example", "Northstar"},
		{"riverside.example", "northstar.example", "Riverside"},
		{"foreign.example", "northstar.example", ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://"+tc.host+"/branding", nil)
		req.Header.Set("X-Forwarded-Host", tc.forwarded)
		req.Header.Set("X-Probectl-Brand-Tenant", siblingBrandTenant)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		var got branding.Branding
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil ||
			got.CustomerName() != tc.name || got.CustomerDomain != (tc.name != "") ||
			rr.Header().Get("X-Probectl-Brand-Tenant") != "" ||
			rr.Header().Get("Cache-Control") != "private, no-store" ||
			rr.Header().Get("Vary") != "Host, Cookie, Authorization" {
			t.Fatalf("bad presentation for actual host %s: %d", tc.host, rr.Code)
		}
	}
	for _, tc := range []struct{ tenant, host, name string }{
		{mappedBrandTenant, "northstar.example", "Northstar"},
		{mappedBrandTenant, "riverside.example", ""},
		{siblingBrandTenant, "northstar.example", ""},
		{siblingBrandTenant, "riverside.example", "Riverside"},
		{siblingBrandTenant, "shared.example", "Riverside"},
	} {
		st := &subjectAttributeSessionStore{session: &auth.Session{TenantID: tc.tenant}}
		srv.sessions = auth.NewManager(st, time.Hour, true, nil)
		req := httptest.NewRequest(http.MethodGet, "https://"+tc.host+"/branding", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "paired-fixture"})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		var got branding.Branding
		expectedTenant := ""
		if tc.name != "" {
			expectedTenant = tc.tenant
		}
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil || got.CustomerName() != tc.name ||
			got.CustomerDomain != (tc.host != "shared.example") ||
			rr.Header().Get("X-Probectl-Brand-Tenant") != expectedTenant ||
			rr.Header().Get("Set-Cookie") != "" {
			t.Fatalf("host %s presented unexpected branding for %s: %d, %s", tc.host, tc.tenant, rr.Code, rr.Body.String())
		}
	}
	srv.sessions = auth.NewManager(&unavailableBrandSessionStore{}, time.Hour, true, nil)
	for _, tc := range []struct{ host, name string }{
		{"northstar.example", "Northstar"},
		{"riverside.example", "Riverside"},
		{"shared.example", ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://"+tc.host+"/branding", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "unresolved-fixture"})
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		var got branding.Branding
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &got) != nil ||
			got.CustomerName() != tc.name || got.CustomerDomain != (tc.name != "") ||
			rr.Header().Get("X-Probectl-Brand-Tenant") != "" ||
			rr.Header().Get("Set-Cookie") != "" {
			t.Fatalf("unresolved session affected sign-in branding for %s: %d, %s", tc.host, rr.Code, rr.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "https://northstar.example/auth/login?tenant="+siblingBrandTenant, nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound || rr.Header().Get("Location") != "" {
		t.Fatalf("foreign tenant was selected from a mapped host: %d", rr.Code)
	}
	for _, tc := range []struct{ tenant, host string }{
		{mappedBrandTenant, "northstar.example"},
		{siblingBrandTenant, "riverside.example"},
	} {
		for _, client := range []struct{ accept, destination string }{
			{"text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", "/ui/"},
			{"application/json,text/html;q=0", "/auth/login"},
			{"", "/auth/login"},
		} {
			req := httptest.NewRequest(http.MethodGet, "https://shared.example/auth/login?tenant="+tc.tenant, nil)
			req.Header.Set("Accept", client.accept)
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "https://"+tc.host+client.destination ||
				rr.Header().Get("Set-Cookie") != "" || rr.Header().Get("Cache-Control") != "no-store" ||
				!slices.Contains(rr.Header().Values("Vary"), "Accept") {
				t.Fatalf("shared sign-in link did not select %s%s for Accept %q: %d, %s", tc.host, client.destination, client.accept, rr.Code, rr.Header().Get("Location"))
			}
		}
	}
	for _, tc := range []struct {
		host, tenant string
		status       int
	}{
		{"northstar.example", mappedBrandTenant, http.StatusOK},
		{"northstar.example", siblingBrandTenant, http.StatusUnauthorized},
		{"riverside.example", mappedBrandTenant, http.StatusUnauthorized},
		{"riverside.example", siblingBrandTenant, http.StatusOK},
		{"shared.example", siblingBrandTenant, http.StatusOK},
		{"unavailable.example", mappedBrandTenant, http.StatusServiceUnavailable},
	} {
		principal := &auth.Principal{TenantID: tc.tenant, Permissions: map[string]bool{permDiagnosticsRead: true}}
		req := httptest.NewRequest(http.MethodGet, "https://"+tc.host+"/v1/editions", nil)
		req.Header.Set("X-Forwarded-Host", "shared.example")
		req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != tc.status {
			t.Errorf("host %s tenant %s returned %d, want %d", tc.host, tc.tenant, rr.Code, tc.status)
		}
	}
	for _, tc := range []struct {
		callback string
		matches  bool
	}{
		{"https://northstar.example/auth/callback", true},
		{"https://NORTHSTAR.example:443/auth/callback", true},
		{"https://northstar.example:8443/auth/callback", false},
		{"https://northstar.example./auth/callback", false},
		{"https://riverside.example/auth/callback", false},
		{"https://northstar.example/auth/callback?next=elsewhere", false},
		{"https://northstar.example/%61uth/callback", false},
	} {
		if got := customerCallbackMatches(tc.callback, "northstar.example"); got != tc.matches {
			t.Errorf("callback %s match = %t, want %t", tc.callback, got, tc.matches)
		}
	}
	factory := newOIDCFactory(srv.cfg, nil)
	records := &unitTenantIDPSource{items: map[string]*store.TenantIDP{
		mappedBrandTenant: {
			Enabled: true, Issuer: "https://idp.northstar.example", ClientID: "northstar", ClientSecret: "fixture",
			RedirectURL: "https://riverside.example/auth/callback",
		},
		siblingBrandTenant: {
			Enabled: true, Issuer: "https://idp.riverside.example", ClientID: "riverside", ClientSecret: "fixture",
			RedirectURL: "https://riverside.example/auth/callback",
		},
	}}
	factory.idps = records
	discoveries := 0
	factory.build = func(_ context.Context, cfg auth.OIDCConfig) (auth.Provider, error) {
		discoveries++
		return unitOIDCProvider{issuer: cfg.Issuer + "/authorize"}, nil
	}
	srv.setSSOProviderFactory(factory)
	login := func(host string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://"+host+"/auth/login", nil))
		return rr
	}
	if rr := login("northstar.example"); rr.Code != http.StatusServiceUnavailable ||
		rr.Header().Get("Location") != "" || discoveries != 0 {
		t.Fatalf("wrong callback reached discovery or redirected: %d, %s", rr.Code, rr.Header().Get("Location"))
	}
	records.items[mappedBrandTenant].RedirectURL = "https://northstar.example/auth/callback"
	for _, host := range []string{"riverside.example", "northstar.example"} {
		rr := login(host)
		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "https://idp."+host+"/authorize" {
			t.Fatalf("sign-in selected the wrong IdP on %s: %d, %s", host, rr.Code, rr.Header().Get("Location"))
		}
	}
	for _, tenant := range []string{mappedBrandTenant, siblingBrandTenant} {
		store := &subjectAttributeSessionStore{session: &auth.Session{TenantID: tenant}}
		srv.sessions = auth.NewManager(store, time.Hour, true, nil)
		srv.authn = auth.NewAuthenticator(srv.sessions, subjectAttributePermissions{keys: []string{permDiagnosticsRead}})
		request := httptest.NewRequest(http.MethodGet, "https://northstar.example/v1/editions", nil)
		request.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "stale-permissions-fixture"})
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, request)
		issued := response.Header().Get("Set-Cookie") != ""
		rotated := len(store.session.AuthorizationHash) != 0
		if tenant == mappedBrandTenant {
			if response.Code != http.StatusOK || !issued || !rotated {
				t.Fatal("the customer host refused normal session rotation for its own tenant")
			}
		} else if response.Code != http.StatusUnauthorized || issued || rotated {
			t.Fatal("the customer host rotated or authorized a different tenant's session")
		}
	}
}
