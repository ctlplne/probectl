// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestControlEvidenceKeepsTheSelectedControlAndTenantScope(t *testing.T) {
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	collected := time.Date(2026, 11, 18, 14, 0, 0, 57, time.UTC)
	for _, tc := range []struct {
		tenant string
		input  SectionInput
	}{
		{"primary-tenant-id", SectionInput{Kind: SectionAuditChain, Status: StatusVerified, Content: map[string]int64{"retained_events": 3}}},
		{"paired-tenant-id", SectionInput{Kind: SectionAuditChain, Status: StatusUnavailable, Reason: "No audit events were retained."}},
	} {
		t.Run(tc.input.Status, func(t *testing.T) {
			manifest, attachments, err := BuildControlEvidence(ControlEvidenceInput{
				TenantID: tc.tenant, Reference: CMMCAuditControl, CollectedAt: collected, Evidence: tc.input,
			})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := SignAuditorBundle(manifest, attachments, private)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := VerifyEvidenceBundle(raw)
			wantScope := hex.EncodeToString(crypto.Hash([]byte("probectl-auditor-scope/v1|" + tc.tenant)))
			if err != nil || verified.Contract != ControlEvidenceContract || verified.Control == nil ||
				verified.Control.Reference != CMMCAuditControl || !verified.Control.CollectedAt.Equal(collected) || verified.TenantScopeDigest != wantScope ||
				len(verified.Sections) != 1 || verified.Sections[0].Kind != SectionAuditChain || verified.Sections[0].Status != tc.input.Status {
				t.Fatal("signed control lost its own scope, time or evidence", err)
			}
			if strings.Contains(string(raw), "primary-tenant-id") || strings.Contains(string(raw), "paired-tenant-id") {
				t.Fatal("signed control package disclosed a raw tenant identifier")
			}
			if _, err := VerifyAuditorBundle(raw); err == nil {
				t.Fatal("the generic auditor contract accepted a single-control package")
			}
		})
	}
	bad := ControlEvidenceInput{TenantID: "primary-tenant-id", Reference: CMMCAuditControl, CollectedAt: collected,
		Evidence: SectionInput{Kind: SectionSegmentation, Status: StatusObserved, Reason: "Declared scope observed.", Content: "fixture"}}
	if _, _, err := BuildControlEvidence(bad); err == nil {
		t.Fatal("an audit control accepted a different evidence source")
	}
}
