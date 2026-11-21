// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestDeviceConfigPolicyBrowserShowsOwnedRulesAndEvidence(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithDeviceOps(device.NewPostgresOpsStore(f.pool))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "device-policy-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	binding := configPolicyBindingInput{ContextID: f.contextID, DeviceEntityID: f.routerID, AgentID: "role-snmp", SourceRef: "192.0.2.1"}
	ruleIDs := [2]string{"west-clock-rule", "east-clock-rule"}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "metrics.write")
		})
		rules := []device.ConfigPolicyRule{{ID: ruleIDs[lane], Mode: device.ConfigRuleTemplate, Template: device.ConfigPolicyIOSNTP}}
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPut, "/v1/device/config-policy",
			map[string]any{"binding": binding, "expected_revision": "0", "rules": rules}, http.StatusOK)
		config := [2]string{"version 17.9\nno ntp server 192.0.2.33\nend\n", "version 17.9\nntp server 192.0.2.33\nend\n"}[lane]
		callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/device/configs",
			map[string]any{"device": "shared-device-name", "binding": binding, "content": config}, http.StatusCreated)
	}
	for lane, tenant := range f.tenants {
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("tenant-%d-%s", lane, theme), func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{URL: socket.URL + "/ui/planes/device",
					Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}}, TrustCertFiles: []string{ca},
					CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Steps: []testsupport.RenderStep{
						{Click: "Configuration policy", Expect: []string{"Rule revision 1", ruleIDs[lane], [2]string{"Violation", "Pass"}[lane], "Download CSV"},
							Absent: []string{ruleIDs[1-lane]}, ExpectWithin: `[role="dialog"]`},
					}})
			})
		}
	}
}
