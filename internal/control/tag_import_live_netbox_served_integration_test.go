// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestStockNetBoxPreviewStaysTenantScopedInServedAdmin(t *testing.T) {
	const required = "PROBECTL_TEST_NETBOX_SERVE_REQUIRED"
	if os.Getenv(required) != "1" {
		testsupport.SkipOptIn(t, required, "requires the stock NetBox TLS fixture and the built browser bundle")
	}
	const runtime = "/tmp/probectl-qa-beta-netbox"
	if os.Getenv("PROBECTL_TEST_NETBOX_FIXTURE") != runtime+"/manifest.json" {
		t.Fatal("required NetBox manifest is outside the owned stock fixture")
	}
	body, err := os.ReadFile(runtime + "/manifest.json")
	if err != nil {
		t.Fatal("read the stock NetBox manifest", err)
	}
	var manifest struct {
		Origin      string            `json:"origin"`
		CAFile      string            `json:"ca_file"`
		TokenFile   string            `json:"token_file"`
		DialAddress string            `json:"dial_address"`
		Tenants     map[string]string `json:"tenants"`
	}
	if json.Unmarshal(body, &manifest) != nil || manifest.Origin != "https://localhost:18443" ||
		manifest.CAFile != runtime+"/ca.crt" || manifest.TokenFile != runtime+"/token" ||
		manifest.Tenants["a"] == "" || manifest.Tenants["b"] == "" || manifest.Tenants["a"] == manifest.Tenants["b"] {
		t.Fatal("invalid owned stock NetBox manifest")
	}
	dest, err := netip.ParseAddrPort(manifest.DialAddress)
	if err != nil || !dest.Addr().Is4() || !dest.Addr().IsPrivate() || dest.Port() != 8443 {
		t.Fatal("owned stock NetBox dial must use its private fixture network")
	}
	t.Setenv("SSL_CERT_FILE", manifest.CAFile)
	secret, err := os.ReadFile(manifest.TokenFile)
	if err != nil || len(secret) == 0 {
		t.Fatal("read-only fixture token is unavailable")
	}
	endpoint := relayStockNetBoxTLS(t, dest)
	f := seedTagImportSubjects(t)
	cfg := &config.Config{AuthMode: "session", HSTSEnabled: true, HSTSMaxAge: time.Hour,
		CMDBProvider: "netbox", CMDBURL: endpoint, CMDBSecret: strings.TrimSpace(string(secret)), CMDBCacheTTL: time.Hour,
		CMDBNetBoxTenantMap: map[string]string{f.a: manifest.Tenants["a"], f.b: manifest.Tenants["b"]}}
	t.Cleanup(func() { mutateOwnedStockNetBox(t, "restore-ip", "a") })
	checkNetBoxServedOwnership(t, f, cfg, [2]string{"role-a", "role-b"}, func() {
		mutateOwnedStockNetBox(t, "move-ip", "a", "b")
	})
}

func checkNetBoxServedOwnership(t *testing.T, f *tagImportSubjectFixture, cfg *config.Config, expected [2]string, moveOwnership func()) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	resolver := BuildCMDB(cfg, log)
	srv := New(cfg, log, f.db, f.db.Pool(), nil, nil).WithTenantStatus(NewTenantStatusCache(f.db.Pool(), 0)).WithCMDB(resolver)
	base, ca := serveDDoSBrowserFixture(t, &roleExplanationAPIFixture{server: srv})
	lanes := [2]string{f.a, f.b}
	var cookies [2]string
	for lane, tenant := range lanes {
		cookies[lane] = issueNetBoxBrowserSession(t, srv, f.db, tenant)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if observed, err := resolver.Lookup(ctx, "192.0.2.10"); err != nil || len(observed) != 1 {
			t.Fatalf("tenant %d did not warm its own NetBox object: %v", lane, err)
		}
	}
	for lane, want := range expected {
		for _, theme := range []string{"light", "dark"} {
			t.Run(want+"-"+theme, func(t *testing.T) {
				renderStockNetBoxPreview(t, f, base.URL, ca, cookies[lane], theme, want, []string{expected[1-lane]})
			})
		}
	}
	moveOwnership()
	for lane, tenant := range lanes {
		t.Run("ownership-changed-"+[]string{"a", "b"}[lane], func(t *testing.T) {
			renderStockNetBoxPreview(t, f, base.URL, ca, cookies[lane], "light",
				"no unambiguous NetBox tag candidate", []string{expected[0], expected[1], "Fresh NetBox tag preview"})
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			if lane == 0 {
				if observed, err := resolver.Lookup(ctx, "192.0.2.10"); err != nil || len(observed) != 0 {
					t.Fatal("the served refusal left the previous owner's value in the warm resolver", err)
				}
			}
		})
	}
}

func issueNetBoxBrowserSession(t *testing.T, srv *Server, db *store.DB, tenant string) string {
	t.Helper()
	var userID string
	var grants []auth.PermissionGrant
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (store.Users{}).Create(ctx, sc, "operator@"+tenant+".invalid", "NetBox reviewer")
		if err != nil {
			return err
		}
		userID = user.ID
		role, err := (store.Roles{}).Create(ctx, sc, "netbox-preview-reader", "NetBox preview reader", "Stock source preview proof")
		if err != nil {
			return err
		}
		for _, permission := range []string{"tenant.read", "entities.read", "tags.read", "cmdb.read", permMetricsRead} {
			if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
				return err
			}
		}
		if err := (store.RoleBindings{}).Bind(ctx, sc, "user", userID, role.ID); err != nil {
			return err
		}
		grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", userID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cookie, err := srv.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: userID,
		Email: "operator@" + tenant + ".invalid", DisplayName: "NetBox reviewer", MFASatisfied: true,
		AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func renderStockNetBoxPreview(t *testing.T, f *tagImportSubjectFixture, origin, ca, cookie, theme, want string, absent []string) {
	t.Helper()
	const card = "[data-tenant-netbox-tag-preview]"
	field := func(label, tag string) string { return card + " label:text-is('" + label + "') + div " + tag }
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL: origin + "/ui/admin", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
		CAFile: ca, TrustCertFiles: []string{ca}, Theme: theme, Accessibility: true, TimeoutMs: 60000,
		Expect: []string{"NetBox tag preview"},
		Steps: []testsupport.RenderStep{
			{Select: field("NetBox preview routing context", "select"), Value: f.contextID},
			{Select: field("NetBox preview tag key", "select"), Value: f.tagID},
			{Select: field("NetBox target kind", "select"), Value: "device"},
			{Fill: field("NetBox target ID", "input"), Value: f.device},
			{Select: field("NetBox source field", "select"), Value: "role"},
			{Click: "Preview NetBox value", Within: card, ExpectWithin: card, Expect: []string{want}, Absent: absent},
		},
	})
}

func mutateOwnedStockNetBox(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", append([]string{"../../scripts/ci_netbox.py"}, args...)...)
	if err := cmd.Run(); err != nil {
		t.Fatal("change the owned NetBox fixture", err)
	}
}

// The internal Docker network deliberately publishes no port. This relay
// forwards only the fixture's TLS connection and leaves verification with
// the same production HTTPS client using the fixture CA and localhost SNI.
func relayStockNetBoxTLS(t *testing.T, dest netip.AddrPort) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer client.Close()
				upstream, err := net.DialTimeout("tcp4", dest.String(), 4*time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_ = client.SetDeadline(time.Now().Add(12 * time.Second))
				_ = upstream.SetDeadline(time.Now().Add(12 * time.Second))
				sent := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, client); close(sent) }()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
				<-sent
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		workers.Wait()
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "https://localhost:" + port
}
