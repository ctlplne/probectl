// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
)

type complianceFlowEvidence struct {
	SelectedPoints        int                  `json:"selected_points"`
	CurrentPoints         int                  `json:"points_with_current_sources"`
	RetainedRows          int                  `json:"retained_rows"`
	AttestedRows          int                  `json:"attested_rows"`
	UnavailableOriginals  int                  `json:"unavailable_originals"`
	FirstObserved         time.Time            `json:"first_observed"`
	LastObserved          time.Time            `json:"last_observed"`
	SelectedSourcesDigest string               `json:"selected_sources_sha256"`
	CaptureOwnersDigest   string               `json:"capture_owners_sha256"`
	ObservationsDigest    string               `json:"observations_sha256"`
	PolicyDigest          string               `json:"policy_sha256,omitempty"`
	Segmentation          *compliance.Evidence `json:"segmentation,omitempty"`
}

func projectComplianceFlowControl(ctx context.Context, tenant, reference, policyDocument, protectedZone string, window complianceFlowWindow) (compliance.SectionInput, error) {
	kind := compliance.ControlEvidenceSection(reference)
	if kind != compliance.SectionSegmentation && kind != compliance.SectionNetworkMonitoring {
		return compliance.SectionInput{}, apierror.Validation("the selected control requires a supported flow evidence source")
	}
	var evaluator *compliance.Engine
	if kind == compliance.SectionSegmentation {
		policy, err := compileComplianceFlowPolicy(reference, policyDocument, protectedZone)
		if err != nil {
			return compliance.SectionInput{}, err
		}
		evaluator, err = compliance.NewTenantEngine(map[string][]compliance.Policy{tenant: {policy}})
		if err != nil {
			return compliance.SectionInput{}, err
		}
	}
	if window.rawCoverageGap {
		return unavailable(kind, "Raw flow retention could not cover the complete requested observation window."), nil
	}
	if len(window.attested) == 0 {
		return unavailable(kind, fmt.Sprintf("None of the %d retained flows from %d selected measurement points had current original-source evidence.", window.observed, len(window.sources))), nil
	}
	coverage, err := collectComplianceFlowEvidence(ctx, tenant, window, evaluator)
	if err != nil {
		return compliance.SectionInput{}, err
	}
	if evaluator == nil {
		return compliance.SectionInput{Kind: kind, Status: compliance.StatusObserved, Content: coverage,
			Reason: "Evidence describes the measured network monitoring coverage for the selected sources and interval."}, nil
	}
	evidence, err := evaluator.Export(tenant)
	if err != nil {
		return compliance.SectionInput{}, err
	}
	evidence.Tenant = ""
	coverage.Segmentation = &evidence
	coverage.PolicyDigest = hex.EncodeToString(crypto.Hash([]byte(policyDocument)))
	observed := 0
	for _, record := range evidence.Records {
		if record.Result.Verdict == compliance.VerdictViolation {
			return compliance.SectionInput{Kind: kind, Status: compliance.StatusFailed, Content: coverage,
				Reason: "Attested traffic violated a declared segmentation rule in the observation window."}, nil
		}
		if record.Result.Verdict == compliance.VerdictObservedClean {
			observed++
		}
	}
	if observed == 0 {
		return unavailable(kind, fmt.Sprintf("The %d attested flows covered none of the %d declared zone pairs in the observation window.", len(window.attested), len(evidence.Records))), nil
	}
	return compliance.SectionInput{Kind: kind, Status: compliance.StatusObserved, Content: coverage,
		Reason: fmt.Sprintf("Attested traffic covered %d of %d declared rules in the observation window.", observed, len(evidence.Records))}, nil
}

func collectComplianceFlowEvidence(ctx context.Context, tenant string, window complianceFlowWindow, evaluator *compliance.Engine) (complianceFlowEvidence, error) {
	coverage := complianceFlowEvidence{SelectedPoints: len(window.sources), RetainedRows: window.observed,
		AttestedRows: len(window.attested), UnavailableOriginals: window.observed - len(window.attested),
		SelectedSourcesDigest: window.sourceDigest, CaptureOwnersDigest: window.captureDigest}
	for _, source := range window.sources {
		if len(source.Selections) > 0 {
			coverage.CurrentPoints++
		}
	}
	digest := []byte("probectl-compliance-flow-observations/v1")
	for _, row := range window.attested {
		if row.TenantID != tenant || row.TS.Before(window.from) || !row.TS.Before(window.to) {
			return complianceFlowEvidence{}, entity.ErrScopeMismatch
		}
		observation := compliance.FlowObs{Src: row.SrcAddr, Dst: row.DstAddr, DstPort: row.DstPort, Bytes: row.Bytes, Source: "flow", At: row.TS}
		var err error
		digest, err = hashFlowRoleInputs(ctx, digest, []any{observation, row.RoutingCaptureKey, row.RawFlowDigest, row.Packets, row.Sampling}, 4096)
		if err != nil {
			return complianceFlowEvidence{}, err
		}
		if coverage.FirstObserved.IsZero() || row.TS.Before(coverage.FirstObserved) {
			coverage.FirstObserved = row.TS
		}
		if row.TS.After(coverage.LastObserved) {
			coverage.LastObserved = row.TS
		}
		if evaluator != nil {
			evaluator.Observe(tenant, observation)
		}
	}
	coverage.ObservationsDigest = hex.EncodeToString(digest)
	return coverage, nil
}

func compileComplianceFlowPolicy(reference, document, protectedZone string) (compliance.Policy, error) {
	policy, err := compliance.ParsePolicy([]byte(document))
	if err != nil {
		return compliance.Policy{}, apierror.Validation("the selected segmentation policy is invalid")
	}
	policy, err = compliance.PolicyForControl(policy, reference, protectedZone)
	if err != nil {
		return compliance.Policy{}, apierror.Validation(err.Error())
	}
	return policy, nil
}
