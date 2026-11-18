// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const (
	ControlEvidenceContract = "probectl-control-evidence/v1"
	CMMCAuditControl        = "AU.L2-3.3.1"
)

type ControlEvidenceScope struct {
	Framework    string    `json:"framework"`
	GuideVersion string    `json:"assessment_guide_version"`
	Reference    string    `json:"reference"`
	CollectedAt  time.Time `json:"collected_at"`
}

type ControlEvidenceInput struct {
	TenantID    string
	Reference   string
	CollectedAt time.Time
	Deployment  DeploymentIdentity
	Evidence    SectionInput
}

// BuildControlEvidence prepares one explicitly selected control for the
// portable signer. A chain check is point-in-time evidence on the retained
// probectl stream. The assessment and applicability are the auditor's work.
func BuildControlEvidence(in ControlEvidenceInput) (AuditorManifest, []Attachment, error) {
	tenant := strings.TrimSpace(in.TenantID)
	if tenant == "" || tenant != in.TenantID || in.CollectedAt.IsZero() {
		return AuditorManifest{}, nil, fmt.Errorf("compliance: control evidence requires a tenant and collection time")
	}
	if in.Reference != CMMCAuditControl || in.Evidence.Kind != SectionAuditChain {
		return AuditorManifest{}, nil, fmt.Errorf("compliance: unsupported control evidence source")
	}
	if in.Evidence.Status == StatusUnavailable && in.Evidence.Content != nil {
		return AuditorManifest{}, nil, fmt.Errorf("compliance: unavailable control evidence cannot publish an attachment")
	}
	section, attachment, err := buildAuditorSection(in.Evidence)
	if err != nil {
		return AuditorManifest{}, nil, err
	}
	collected := in.CollectedAt.UTC()
	scope := crypto.Hash([]byte("probectl-auditor-scope/v1|" + tenant))
	id := crypto.Hash([]byte(ControlEvidenceContract + "|" + tenant + "|" + in.Reference + "|" + collected.Format(time.RFC3339Nano)))
	manifest := AuditorManifest{
		Contract: ControlEvidenceContract, BundleID: hex.EncodeToString(id[:16]),
		Control:           &ControlEvidenceScope{Framework: "CMMC Level 2", GuideVersion: "2.13", Reference: in.Reference, CollectedAt: collected},
		TenantScopeDigest: hex.EncodeToString(scope), CreatedAt: collected, Deployment: in.Deployment,
		Redaction: "tenant-scoped audit sequence coverage without event payloads or identities",
		Sections:  []AuditorSection{section}, Frameworks: []FrameworkMapping{},
		Caveats: []string{
			"This package supports the selected control for the retained probectl audit stream at collection time.",
			"The assessor uses this evidence alongside the required assessments to determine compliance.",
		},
	}
	var attachments []Attachment
	if attachment != nil {
		attachments = append(attachments, *attachment)
	}
	if err := validateControlEvidenceManifest(manifest, attachments); err != nil {
		return AuditorManifest{}, nil, err
	}
	return manifest, attachments, nil
}

func validateControlEvidenceManifest(manifest AuditorManifest, attachments []Attachment) error {
	scope := manifest.Control
	digest, digestErr := hex.DecodeString(manifest.TenantScopeDigest)
	if scope == nil || scope.Reference != CMMCAuditControl || scope.Framework != "CMMC Level 2" || scope.GuideVersion != "2.13" ||
		scope.CollectedAt.IsZero() || !scope.CollectedAt.Equal(manifest.CreatedAt) || digestErr != nil || len(digest) != 32 ||
		len(manifest.Sections) != 1 || manifest.Sections[0].Kind != SectionAuditChain || len(manifest.Caveats) == 0 {
		return fmt.Errorf("compliance: invalid control evidence scope or source")
	}
	section := manifest.Sections[0]
	switch section.Status {
	case StatusUnavailable:
		if len(attachments) == 0 && section.Digest == "" && section.MediaType == "" && strings.TrimSpace(section.Reason) != "" {
			return nil
		}
	case StatusFailed, StatusVerified:
		if len(attachments) == 1 && section.Digest != "" && section.Digest == attachments[0].Digest &&
			section.MediaType == "application/json" && attachments[0].MediaType == section.MediaType &&
			(section.Status != StatusFailed || strings.TrimSpace(section.Reason) != "") {
			return nil
		}
	}
	return fmt.Errorf("compliance: invalid control evidence attachment or status")
}
