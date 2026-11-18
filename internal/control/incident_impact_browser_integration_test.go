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
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// This uses modeled captures and the real tenant session, production UI,
// authority snapshot and signed downloaded evidence. Physical flow and
// a positive retained weekly baseline have separate release proofs.
func TestIncidentImpactBrowserDownloadsCompleteOwnedEvidenceInBothThemes(t *testing.T) {
	f, incidents := seedIncidentImpactFlowFixture(t)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	to := time.Now().UTC()
	from := to.Add(-time.Minute)
	for lane, tenant := range f.tenants {
		foreign := f.tenants[1-lane]
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "impact@local.invalid", DisplayName: "Incident operator", AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		for _, theme := range []string{"light", "dark"} {
			t.Run(strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				const result = `[aria-label="Incident impact result"]`
				wantBytes := strconv.Itoa((100 + lane) * 3)
				field := func(label string) string { return "label:text-is(" + strconv.Quote(label) + ") + div input" }
				download := filepath.Join(t.TempDir(), "impact.evidence.json")
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL:     socket.URL + "/ui/incidents?incident=" + url.QueryEscape(incidents[tenant]),
					Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}}, TrustCertFiles: []string{ca}, CAFile: ca,
					Theme: theme, Accessibility: true, Expect: []string{"Traffic and customer impact"}, Absent: []string{"customer-" + foreign},
					Steps: []testsupport.RenderStep{
						{Fill: field("Impact from (ISO 8601 with offset)"), Value: from.Format(time.RFC3339Nano)},
						{Fill: field("Impact to (exclusive, ISO 8601 with offset)"), Value: to.Format(time.RFC3339Nano)},
						{Fill: field("Customer tag key (optional)"), Value: "customer"},
						{Click: "Compare incident impact", ExpectWithin: result, Expect: []string{"Current observed traffic", wantBytes, "One week earlier", "No observed records in this window", "customer-" + tenant}},
						{Click: "Export signed impact evidence", Within: result, Download: download},
					},
				})
				raw, err := os.ReadFile(download)
				if err != nil {
					t.Fatal(err)
				}
				checkIncidentImpactBrowserDownload(t, raw, incidents[tenant], foreign, wantBytes)
			})
		}
	}
}

func checkIncidentImpactBrowserDownload(t *testing.T, raw []byte, id, foreign, wantBytes string) {
	t.Helper()
	manifest, err := evidence.Verify(raw)
	if err != nil || manifest.TenantScopeDigest == "" || bytes.Contains(raw, []byte(foreign)) {
		t.Fatal("browser did not download private, signed impact evidence", err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}
	for _, record := range manifest.Evidence {
		if record.Kind != "incident.impact" {
			continue
		}
		for _, attachment := range pkg.Attachments {
			if attachment.Digest != record.AttachmentDigest {
				continue
			}
			var impact incident.ImpactResponse
			if err := json.Unmarshal(attachment.Content, &impact); err != nil || impact.IncidentID != id ||
				impact.Current.ObservedTotals == nil || impact.Current.ObservedTotals.ScaledBytes != wantBytes ||
				len(impact.Current.Captures) != 1 || len(impact.Customers) != 1 || impact.Previous.ObservedTotals != nil {
				t.Fatal("download lost original impact, ownership, customer coverage or the missing baseline", err)
			}
			return
		}
	}
	t.Fatal("download omitted the requested signed impact attachment")
}
