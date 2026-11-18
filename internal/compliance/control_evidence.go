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
	ControlEvidenceContract   = "probectl-control-evidence/v1"
	CMMCAuditControl          = "AU.L2-3.3.1"
	CMMCBoundaryControl       = "SC.L2-3.13.1"
	CMMCMonitoringControl     = "SI.L2-3.14.6"
	PCISegmentationControl    = "11.4.5"
	PCIInboundNetworkControl  = "1.3.1"
	PCIOutboundNetworkControl = "1.3.2"
	SectionNetworkMonitoring  = "network-monitoring-coverage"
)

type ControlEvidenceScope struct {
	Framework       string                 `json:"framework"`
	GuideVersion    string                 `json:"assessment_guide_version,omitempty"`
	StandardVersion string                 `json:"standard_version,omitempty"`
	Reference       string                 `json:"reference"`
	ProtectedZone   string                 `json:"protected_zone,omitempty"`
	CollectedAt     time.Time              `json:"collected_at"`
	Window          *ControlEvidenceWindow `json:"observation_window,omitempty"`
}

type ControlEvidenceWindow struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

type ControlEvidenceInput struct {
	TenantID      string
	Reference     string
	ProtectedZone string
	CollectedAt   time.Time
	Deployment    DeploymentIdentity
	Evidence      SectionInput
	Window        *ControlEvidenceWindow
}

type controlEvidenceReference struct{ framework, guide, standard, section string }

func controlEvidenceReferenceFor(reference string) controlEvidenceReference {
	switch reference {
	case CMMCAuditControl:
		return controlEvidenceReference{framework: "CMMC Level 2", guide: "2.13", section: SectionAuditChain}
	case CMMCBoundaryControl:
		return controlEvidenceReference{framework: "CMMC Level 2", guide: "2.13", section: SectionSegmentation}
	case CMMCMonitoringControl:
		return controlEvidenceReference{framework: "CMMC Level 2", guide: "2.13", section: SectionNetworkMonitoring}
	case PCISegmentationControl, PCIInboundNetworkControl, PCIOutboundNetworkControl:
		return controlEvidenceReference{framework: "PCI DSS", standard: "4.0.1", section: SectionSegmentation}
	default:
		return controlEvidenceReference{}
	}
}

// ControlEvidenceSection identifies the measured source for a supported ref.
func ControlEvidenceSection(reference string) string {
	return controlEvidenceReferenceFor(reference).section
}

// BuildControlEvidence prepares one explicitly selected control for the
// portable signer. A chain check is point-in-time evidence on the retained
// probectl stream. The assessment and applicability are the auditor's work.
func BuildControlEvidence(in ControlEvidenceInput) (AuditorManifest, []Attachment, error) {
	tenant := strings.TrimSpace(in.TenantID)
	if tenant == "" || tenant != in.TenantID || in.CollectedAt.IsZero() {
		return AuditorManifest{}, nil, fmt.Errorf("compliance: control evidence requires a tenant and collection time")
	}
	ref := controlEvidenceReferenceFor(in.Reference)
	if ref.section == "" || in.Evidence.Kind != ref.section {
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
	var window *ControlEvidenceWindow
	if in.Window != nil {
		window = &ControlEvidenceWindow{From: in.Window.From.UTC(), To: in.Window.To.UTC()}
	}
	scope := crypto.Hash([]byte("probectl-auditor-scope/v1|" + tenant))
	id := crypto.Hash([]byte(ControlEvidenceContract + "|" + tenant + "|" + in.Reference + "|" + collected.Format(time.RFC3339Nano)))
	manifest := AuditorManifest{
		Contract: ControlEvidenceContract, BundleID: hex.EncodeToString(id[:16]),
		Control: &ControlEvidenceScope{Framework: ref.framework, GuideVersion: ref.guide, StandardVersion: ref.standard, Reference: in.Reference,
			ProtectedZone: in.ProtectedZone, CollectedAt: collected, Window: window},
		TenantScopeDigest: hex.EncodeToString(scope), CreatedAt: collected, Deployment: in.Deployment,
		Redaction: "tenant-scoped audit sequence coverage without event payloads or identities",
		Sections:  []AuditorSection{section}, Frameworks: []FrameworkMapping{},
		Caveats: []string{
			"This package supports the selected control for the retained probectl audit stream at collection time.",
			"The assessor uses this evidence alongside the required assessments to determine compliance.",
		},
	}
	if ref.section != SectionAuditChain {
		manifest.Redaction = "selected tenant-scoped flow and coverage evidence"
		manifest.Caveats[0] = "This package supports the selected control for the measured flow sources and signed observation window."
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
	if scope == nil {
		return fmt.Errorf("compliance: invalid control evidence scope or source")
	}
	ref := controlEvidenceReferenceFor(scope.Reference)
	digest, digestErr := hex.DecodeString(manifest.TenantScopeDigest)
	if ref.section == "" || scope.Framework != ref.framework || scope.GuideVersion != ref.guide || scope.StandardVersion != ref.standard ||
		scope.CollectedAt.IsZero() || !scope.CollectedAt.Equal(manifest.CreatedAt) || digestErr != nil || len(digest) != 32 ||
		len(manifest.Sections) != 1 || manifest.Sections[0].Kind != ref.section || len(manifest.Caveats) == 0 {
		return fmt.Errorf("compliance: invalid control evidence scope or source")
	}
	if usesCardholderZone(scope.Reference) != (scope.ProtectedZone != "") || strings.TrimSpace(scope.ProtectedZone) != scope.ProtectedZone {
		return fmt.Errorf("compliance: invalid cardholder-data zone for the selected control")
	}
	if ref.section == SectionAuditChain && scope.Window != nil || ref.section != SectionAuditChain && !validControlEvidenceWindow(scope.Window, scope.CollectedAt) {
		return fmt.Errorf("compliance: invalid control evidence time window")
	}
	section := manifest.Sections[0]
	switch section.Status {
	case StatusUnavailable:
		if len(attachments) == 0 && section.Digest == "" && section.MediaType == "" && strings.TrimSpace(section.Reason) != "" {
			return nil
		}
	case StatusFailed, StatusVerified, StatusObserved:
		if section.Status == StatusVerified && ref.section != SectionAuditChain || section.Status == StatusObserved && ref.section == SectionAuditChain {
			break
		}
		if len(attachments) == 1 && section.Digest != "" && section.Digest == attachments[0].Digest &&
			section.MediaType == "application/json" && attachments[0].MediaType == section.MediaType &&
			(section.Status == StatusVerified || strings.TrimSpace(section.Reason) != "") {
			return nil
		}
	}
	return fmt.Errorf("compliance: invalid control evidence attachment or status")
}

func validControlEvidenceWindow(window *ControlEvidenceWindow, collected time.Time) bool {
	return window != nil && !window.From.IsZero() && window.To.After(window.From) && !window.To.After(collected)
}
