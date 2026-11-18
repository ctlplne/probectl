// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestPathHealthAlertSourceExportStaysInServedTenantDialog(t *testing.T) {
	proof := newPathHealthAPIFixture(t)
	f := proof.fixture
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	names := []string{"Alpha owned FCS climb", "Beta owned FCS climb"}
	cookies := make([]string, len(f.tenants))
	const metric = "probectl.device.if.in.fcs.errors"
	for lane, tenant := range f.tenants {
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permAlertRead, permAlertWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		input := alert.PathHealthSourceInput{TestID: proof.tests[tenant], InterfaceID: f.interfaceID, Metric: metric}
		body, err := json.Marshal(alertRequest{Name: names[lane], PathHealthSource: &input})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/alerts", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		req.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatal("unable to seed the owned path-error rule", response.StatusCode)
		}
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "alert-source@local.invalid", DisplayName: "Alert operator", AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		cookies[lane] = cookie
	}
	for lane, tenant := range f.tenants {
		for _, theme := range []string{"light", "dark"} {
			t.Run(names[lane]+"/"+theme, func(t *testing.T) {
				const dialog = `[role="dialog"]`
				const yaml = dialog + ` [aria-label="View as YAML"]`
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: socket.URL + "/ui/alerts", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookies[lane]}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true,
					Expect: []string{names[lane], "Stored rules will not fire"}, Absent: []string{names[1-lane], proof.tests[f.tenants[1-lane]]},
					Steps: []testsupport.RenderStep{
						{Click: "Path-error source", Expect: []string{"Path-error source: " + names[lane]}},
						{Click: "Read current path source", Within: dialog, ExpectWithin: dialog, Expect: []string{"Original error counter"}},
						{Click: "Export current source as code", Summary: true, Within: dialog, ExpectWithin: yaml, Expect: []string{proof.tests[tenant], f.interfaceID, metric}},
					},
					Controls: []testsupport.RenderControl{{Role: "button", Name: "Copy YAML", Within: dialog}},
				})
			})
		}
	}
}
