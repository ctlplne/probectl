// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import "time"

type CarrierSLARequest struct {
	Version string `json:"version"`
	At      string `json:"at"`
}

// A population digest commits to every selected original receipt, including
// unavailable observations. It proves reproducibility, not sender authority or
// the existence of continuous measurements between executions.
type CarrierSLAPopulation struct {
	ID                string    `json:"id"`
	ContextID         string    `json:"context_id"`
	DeviceID          string    `json:"device_id"`
	AgentID           string    `json:"agent_id"`
	TestID            string    `json:"test_id"`
	Originals         string    `json:"originals"`
	Successful        string    `json:"successful"`
	Failed            string    `json:"failed"`
	Unknown           string    `json:"unknown"`
	Transmitted       string    `json:"transmitted"`
	Lost              string    `json:"lost"`
	RTTSamples        string    `json:"rtt_samples"`
	Digest            string    `json:"digest"`
	ObservedNotBefore time.Time `json:"observed_not_before"`
}

type CarrierSLAStatement struct {
	Agreement        CapacityAgreement      `json:"agreement"`
	Period           CapacityBillingPeriod  `json:"period"`
	Credit           CarrierSLACredit       `json:"credit"`
	Sources          []CarrierSLAPopulation `json:"sources"`
	AsOf             time.Time              `json:"as_of"`
	SourceValidUntil time.Time              `json:"source_valid_until"`
	CoverageBasis    string                 `json:"coverage_basis"`
	RepairBasis      string                 `json:"repair_basis"`
	HumanReview      bool                   `json:"human_review_required"`
}
