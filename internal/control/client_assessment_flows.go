// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

// Assessment samples reuse pinned saved queries, complete projection and all
// current source checks. Relative windows end at the exact assessment end;
// metadata authority is still captured now. The already-held report fairness
// slot and retained monthly bytes are shared with the flow operation.
func (s *Server) captureAssessmentFlowSample(ctx context.Context, actor *auth.Principal, refs []reportFlowSourceRef, monthly *reportFlowCapture) (_ *reportFlowCapture, captureErr error) {
	defer func() {
		if captureErr != nil {
			monthly.Close()
		}
	}()
	if monthly == nil || monthly.Monthly == nil || monthly.monthlyCapture == nil || monthly.monthlyCapture.Period.Kind != "assessment" {
		return nil, apierror.Validation("flow samples require an explicit assessment")
	}
	options := reportFlowCaptureOptions{PeriodEnd: monthly.Monthly.To, ReservedMemoryBytes: monthly.monthlyCapture.retainedBytes}
	result, err := s.captureFlowSourcesWithOptions(ctx, actor, refs, false, true, options)
	if err != nil {
		return nil, err
	}
	if result.SourceGeneration != monthly.SourceGeneration {
		result.Close()
		return nil, apierror.Conflict("assessment sources changed during capture; retry")
	}
	if err := validateAssessmentFlowWindows(monthly.Monthly, result.Inputs); err != nil {
		result.Close()
		return nil, err
	}
	flowRelease := result.release
	result.release = func() { flowRelease(); monthly.Close() }
	result.Monthly, result.monthlyCapture = monthly.Monthly, monthly.monthlyCapture
	result.Tables = append(monthly.Tables, result.Tables...)
	return result, nil
}

func validateAssessmentFlowWindows(monthly *clientReportSourceRequirements, inputs []reportFlowInput) error {
	if monthly == nil || len(inputs) == 0 {
		return errReportSourceRequirements
	}
	for _, input := range inputs {
		if input.From.Before(monthly.From) || input.To.After(monthly.To) || !input.To.After(input.From) {
			return apierror.Validation("each complete flow sample window must lie inside the assessment interval; change the saved query without truncating its results")
		}
	}
	return nil
}
