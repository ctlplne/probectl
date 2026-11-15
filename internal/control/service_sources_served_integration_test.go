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
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real application-role Postgres/RLS, sessions, HTTPS, production SPA and
// Chromium/axe. Source-format documents are QA-authored, not publisher receipts.
func TestPublishedSourceInspectorServedKeepsTenantReadersAndBothThemes(t *testing.T) {
	f, _, _, _ := newRoleFlowQueryFixture(t)
	fetched := time.Now().UTC().Add(-time.Minute)
	document := map[string]any{"version": 1, "sources": []any{map[string]any{
		"publisher": "aws", "complete": true, "fetched_at": fetched,
		"data": map[string]any{"syncToken": "qa-source-version", "createDate": fetched.Format("2006-01-02-15-04-05"),
			"prefixes": []any{
				map[string]string{"ip_prefix": "192.0.2.0/24", "service": "Published service alpha", "region": "region-a"},
				map[string]string{"ip_prefix": "198.51.100.0/24", "service": "Published service beta", "region": "region-b"},
			}, "ipv6_prefixes": []any{}},
	}}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	en, enabled := BuildEnrichment(&config.Config{FlowEnrichServiceFile: path, FlowEnrichServiceMaxAge: time.Hour, FlowEnrichServiceMemoryBytes: 16 << 20, FlowEnrichCacheMax: 16}, statusQuietLog())
	if !enabled || en == nil {
		t.Fatal("offline source unavailable")
	}
	f.server.WithOpenDataStatus(en, nil, nil)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	addresses := []string{"192.0.2.7", "198.51.100.7"}
	services := []string{"Published service alpha", "Published service beta"}
	for lane, tenant := range f.tenants {
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, scope tenancy.Scope) error {
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, scope, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "source-reader@local.invalid", DisplayName: "Source reader", AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		for _, theme := range []string{"light", "dark"} {
			t.Run(strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: socket.URL + "/ui/explore?native_flow=1", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Expect: []string{"Published service sources · preview"},
					Steps: []testsupport.RenderStep{
						{Fill: "[data-service-sources] label:text-is('Address for service sources') + div input", Value: addresses[lane]},
						{Click: "Look up service sources", Within: "[data-service-sources]", Expect: []string{"aws · matched (1 candidate)"}},
						{Click: "aws · matched (1 candidate)", Within: "[data-service-sources]", ExpectWithin: "[data-service-sources]", Expect: []string{services[lane], "qa-source-version", "Original fetch time", "Original body digest"}, Absent: []string{services[1-lane]}},
					},
				})
			})
		}
	}
}
