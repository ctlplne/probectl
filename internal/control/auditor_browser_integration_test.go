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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// The observations are modeled. Downloads use production assets, TLS,
// PostgreSQL tenant roles and the offline CLI with a separately held signer pin.
func TestAuditorBundleBrowserKeepsCurrentTenantRolesAndBothThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	lanes := []struct {
		policy, status string
		port           int
		verdict        compliance.Verdict
	}{
		{"primary-protected-boundary", compliance.StatusFailed, 443, compliance.VerdictViolation},
		{"paired-protected-boundary", "observed", 8443, compliance.VerdictObservedClean},
	}
	policies := make(map[string][]compliance.Policy, len(lanes))
	for i, tenant := range f.tenants {
		policies[tenant] = []compliance.Policy{auditorBoundaryPolicy(t, lanes[i].policy, lanes[i].port)}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permThreatRead, permAuditRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
	}
	engine, err := compliance.NewTenantEngine(policies)
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		engine.Observe(tenant, compliance.FlowObs{Src: "192.0.2.1", Dst: "198.51.100.1", DstPort: 443, Bytes: 150, Source: "flow", At: time.Now().UTC()})
	}
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f.server.WithCompliance(engine).WithEvidenceSigningKey(private)
	pin := "sha256:" + hex.EncodeToString(crypto.Hash(public))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "auditor-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, tenant := range f.tenants {
		own, sibling := lanes[i], lanes[1-i].policy
		cookie := auditorTestSession(t, f, tenant)
		for _, theme := range []string{"light", "dark"} {
			t.Run(own.policy+"/"+theme, func(t *testing.T) {
				download := filepath.Join(t.TempDir(), "probectl-auditor-bundle.json")
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: socket.URL + "/ui/compliance", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true,
					Expect: []string{own.policy, "Segmentation verdicts", "separate trusted channel", "--expected-fingerprint", "probectl-auditor-bundle.json"},
					Absent: []string{sibling},
					Steps:  []testsupport.RenderStep{{Click: "Download auditor bundle (signed)", Download: download}},
				})
				manifest, raw := verifiedAuditorBundleFile(t, download, pin, tenant)
				if bytes.Contains(raw, []byte(sibling)) || bytes.Contains(raw, []byte(f.tenants[1-i])) {
					t.Fatal("browser download disclosed the sibling tenant")
				}
				for _, section := range manifest.Sections {
					if section.Kind == compliance.SectionSegmentation {
						checkAuditorSegmentationSection(t, raw, section, own.status, own.policy, own.verdict)
						return
					}
				}
				t.Fatal("browser download omitted the segmentation section")
			})
		}
		t.Run(own.policy+"/audit-withdrawn", func(t *testing.T) {
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, tenant, f.roles[tenant], permAuditRead)
				return err
			})
			restricted := auditorTestSession(t, f, tenant)
			for _, endpoint := range []string{"/v1/compliance/evidence", "/v1/compliance/auditor-bundle"} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+endpoint, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: restricted})
				res, err := socket.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if res.StatusCode != http.StatusForbidden || res.Header.Get("Content-Disposition") != "" {
					t.Fatal("audit endpoint did not refuse the restricted session", endpoint, res.StatusCode)
				}
			}
			testsupport.RenderUI(t, testsupport.RenderSpec{
				URL: socket.URL + "/ui/compliance", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: restricted}},
				TrustCertFiles: []string{ca}, CAFile: ca, Theme: "light", Accessibility: true,
				Expect: []string{own.policy, "Segmentation verdicts"},
				Absent: []string{sibling, "Download audit evidence", "Download auditor bundle", "--expected-fingerprint"},
			})
		})
	}
}

func auditorTestSession(t *testing.T, f *roleExplanationAPIFixture, tenant string) string {
	t.Helper()
	var grants []auth.PermissionGrant
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
		return err
	})
	cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{
		TenantID: tenant, UserID: f.users[tenant], Email: "auditor@local.invalid", DisplayName: "Audit operator",
		AuthorizationHash: auth.PermissionGrantFingerprint(grants),
	})
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func verifiedAuditorBundleFile(t *testing.T, filename, pin, tenant string) (compliance.AuditorManifest, []byte) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := []string{"--json", "verify-bundle", "--expected-fingerprint", pin, filename}
	if code := cli.RunWithStdin(args, func(string) string { return "" }, nil, &stdout, &stderr); code != 0 {
		t.Fatal("download failed pinned offline verification", code, stderr.String())
	}
	var verification struct {
		Authenticated bool                       `json:"authenticated"`
		Manifest      compliance.AuditorManifest `json:"manifest"`
	}
	scope := hex.EncodeToString(crypto.Hash([]byte("probectl-auditor-scope/v1|" + tenant)))
	if err := json.Unmarshal(stdout.Bytes(), &verification); err != nil || !verification.Authenticated || verification.Manifest.TenantScopeDigest != scope {
		t.Fatal("verified download lost the signer or requested tenant scope", err)
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return verification.Manifest, raw
}
