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
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Browser downloads use the real session, production bundle and TLS service.
// The original observations are modeled and trace origin remains control plane.
func TestCarrierBrowserDownloadsPinnedTenantEvidenceInBothThemes(t *testing.T) {
	proof := seedCarrierExportFixture(t)
	f := proof.path.fixture
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "carrier-browser-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	field := func(label string) string { return "label:text-is(" + strconv.Quote(label) + ") + div input" }
	for lane, tenant := range f.tenants {
		foreign := f.tenants[1-lane]
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "carrier@local.invalid", DisplayName: "Incident operator", AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		window := proof.windows[tenant]
		for _, theme := range []string{"light", "dark"} {
			t.Run(strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				download := filepath.Join(t.TempDir(), "carrier.json")
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL:            socket.URL + "/ui/incidents?incident=" + url.QueryEscape(proof.ids[tenant]),
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true,
					Expect: []string{"Carrier ticket pack", "separate trusted channel", "probectl-incident-" + proof.ids[tenant] + "-carrier.json --trusted-key-fingerprint"},
					Absent: []string{proof.ids[foreign]},
					Steps: []testsupport.RenderStep{
						{Fill: field("Carrier from (ISO 8601 with offset)"), Value: window.From.Format(time.RFC3339Nano)},
						{Fill: field("Carrier to (exclusive, ISO 8601 with offset)"), Value: window.To.Format(time.RFC3339Nano)},
						{Click: "Download carrier ticket pack", Within: `form[aria-label="Carrier ticket evidence"]`, Download: download},
					},
				})
				verifyCarrierBrowserDownload(t, download, proof, tenant, foreign, lane)
			})
		}
	}
}

func verifyCarrierBrowserDownload(t *testing.T, filename string, proof carrierExportFixture, tenant, foreign string, lane int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env := func(string) string { return "" }
	args := []string{"incident", "verify", filename, "--trusted-key-fingerprint", proof.signer}
	if code := cli.RunWithStdin(args, env, nil, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "VERIFIED ") {
		t.Fatal("download failed pinned offline verification", code)
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{tenant, foreign, proof.ids[foreign], "PRIVATE CUSTOMER", "carrier-fixture-only"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("browser download disclosed a tenant identifier or private incident text")
		}
	}
	manifest, err := evidence.Verify(raw)
	window := proof.windows[tenant]
	if err != nil || manifest.Profile != "carrier" || manifest.Incident.ID != proof.ids[tenant] ||
		!manifest.Window.From.Equal(window.From) || !manifest.Window.To.Equal(window.To) {
		t.Fatal("browser download changed the signed incident, profile or window", err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(raw, &pkg); err != nil || len(pkg.Attachments) != 1 {
		t.Fatal("browser download lost the exclusive carrier attachment", err)
	}
	var pack incident.CarrierPack
	if err := json.Unmarshal(pkg.Attachments[0].Content, &pack); err != nil || pack.ContractVersion != incident.CarrierContractVersion ||
		len(pack.Vantages) != 2 || len(pack.Routing) != 1 || len(pack.Handoffs) != 1 || len(pack.Handoffs[0].Counters) != 2*len(pathHealthMetricNames) ||
		pack.Coverage.Traces != "control_plane_only" || !slices.Contains(pack.Coverage.Missing, "independent_agent_traceroutes") {
		t.Fatal("browser download lost original observations or overstated tracing coverage", err)
	}
	agents := make([]string, 0, len(pack.Vantages))
	for _, vantage := range pack.Vantages {
		agents = append(agents, vantage.AgentID)
		if vantage.Measurements.Packets == nil || vantage.Measurements.Packets.Replies != strconv.Itoa(lane+1) ||
			len(vantage.Traces) != 1 || vantage.Traces[0].Vantage != path.VantageControlPlane {
			t.Fatal("browser download changed the tenant's original replies or trace origin")
		}
	}
	slices.Sort(agents)
	owned := slices.Clone(proof.agents[tenant])
	slices.Sort(owned)
	if !slices.Equal(agents, owned) {
		t.Fatal("browser download changed the exact owned probe agents")
	}
}
