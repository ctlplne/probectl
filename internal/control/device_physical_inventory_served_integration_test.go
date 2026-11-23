// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestPhysicalInventoryBrowserShowsOnlyOwnedComponents(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "physical-inventory-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	source := entity.SourceKey{AgentID: "role-snmp", Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}
	serials := [2]string{"owned-alpha-physical", "owned-beta-physical"}
	seedPhysicalInventoryObservations(t, f, source, serials)
	option, err := json.Marshal([2]string{source.AgentID, source.SourceRef})
	if err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		cookie := seasonalFlowBrowserCookie(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(fmt.Sprintf("tenant-%d-%s", lane, theme), func(t *testing.T) {
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL:            socket.URL + "/ui/planes/device",
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 60000,
					Steps: []testsupport.RenderStep{
						{Click: "Find physical inventory", Gone: true},
						{Select: "#physical-inventory-context", Value: f.contextID},
						{Select: "#physical-inventory-device", Value: f.routerID},
						{Select: "#physical-inventory-source", Value: string(option),
							Expect: []string{serials[lane], "Parent index 0", "Vulnerability coverage unknown."}},
						{Click: "Next components", Expect: []string{serials[lane], "Previous components"}, Gone: true},
					},
					Controls: []testsupport.RenderControl{{Role: "table", Name: "Physical inventory"}},
					Absent:   []string{serials[1-lane]},
				})
			})
		}
	}
}
