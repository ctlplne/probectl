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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAuditorBundleAuditChainStatesTheVerifiedTenantSuffix(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	populated, empty := f.tenants[0], f.tenants[1]
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permAuditRead)
		})
	}
	now := time.Now().UTC()
	f.in(populated, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := audit.AppendAtForTest(ctx, sc, now.Add(-48*time.Hour), "audit-fixture", "audit.retention-fixture", "retired-fixture-event", nil); err != nil {
			return err
		}
		if _, err := audit.AppendAtForTest(ctx, sc, now, "audit-fixture", "audit.retention-fixture", "retained-fixture-event", nil); err != nil {
			return err
		}
		// Model the SIEM acknowledgement for the aged fixture event.
		return (store.SIEMDelivery{}).Advance(ctx, sc, 1)
	})
	if n, err := audit.PruneTenant(t.Context(), f.pool, populated, audit.RetentionPolicy{Window: 24 * time.Hour}, 1, now); err != nil || n != 1 {
		t.Fatal("expected exactly one fixture event pruned", n, err)
	}
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f.server.WithEvidenceSigningKey(private)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	for _, tc := range []struct {
		name, tenant, status string
		bounds               [3]int64
	}{
		// The served route records the export before assembling the bundle.
		{"retained-suffix", populated, compliance.StatusVerified, [3]int64{4, 1, 3}},
		{"empty-before-export", empty, compliance.StatusUnavailable, [3]int64{}},
		{"first-export", empty, compliance.StatusVerified, [3]int64{1, 0, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "probectl-auditor-bundle.json")
			body := readAuditorAuditBundle(t, f, socket, tc.tenant, tc.status == compliance.StatusUnavailable)
			if err := os.WriteFile(file, body, 0o600); err != nil {
				t.Fatal(err)
			}
			pin := "sha256:" + hex.EncodeToString(crypto.Hash(public))
			manifest, raw := verifiedAuditorBundleFile(t, file, pin, tc.tenant)
			for _, private := range []string{populated, empty, "retained-fixture-event", "retired-fixture-event"} {
				if bytes.Contains(raw, []byte(private)) {
					t.Fatal("the signed audit coverage included private event or tenant fields")
				}
			}
			var bundle compliance.AuditorPackage
			if err := json.Unmarshal(raw, &bundle); err != nil {
				t.Fatal(err)
			}
			for _, section := range manifest.Sections {
				if section.Kind == compliance.SectionAuditChain {
					assertAuditorAuditChainSection(t, section, bundle.Attachments, tc.status, tc.bounds)
					return
				}
			}
			t.Fatal("bundle omitted the audit chain section")
		})
	}
}

func readAuditorAuditBundle(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, tenant string, beforeExportAudit bool) []byte {
	t.Helper()
	if beforeExportAudit {
		rec := httptest.NewRecorder()
		if err := f.server.handleAuditorBundle(rec, auditorRequest(t, tenant)); err != nil {
			t.Fatal(err)
		}
		return rec.Body.Bytes()
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/compliance/auditor-bundle", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: auditorTestSession(t, f, tenant)})
	res, err := socket.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatal("signed tenant bundle unavailable", res.StatusCode)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func assertAuditorAuditChainSection(t *testing.T, section compliance.AuditorSection, attachments []compliance.Attachment, status string, bounds [3]int64) {
	t.Helper()
	if section.Status != status {
		t.Fatalf("audit chain section status %q, want %q", section.Status, status)
	}
	if status == compliance.StatusUnavailable {
		if section.Reason == "" || section.Digest != "" {
			t.Fatal("the empty audit stream must have an explicit gap and no attachment")
		}
		return
	}
	for _, attachment := range attachments {
		if attachment.Digest != section.Digest {
			continue
		}
		var coverage struct {
			HeadSequence   int64 `json:"head_sequence"`
			PrunedThrough  int64 `json:"pruned_through"`
			RetainedEvents int64 `json:"retained_events"`
		}
		err := json.Unmarshal(attachment.Content, &coverage)
		got := [3]int64{coverage.HeadSequence, coverage.PrunedThrough, coverage.RetainedEvents}
		if err != nil || got != bounds {
			t.Fatalf("audit chain coverage (head, pruned through, retained events) %v, want %v: %v", got, bounds, err)
		}
		return
	}
	t.Fatal("verified audit chain omitted its coverage attachment")
}
