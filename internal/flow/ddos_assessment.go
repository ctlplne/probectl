// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
)

type DDoSAssessmentInput struct {
	Version                string `json:"version"`
	Prefix                 string `json:"prefix"`
	Direction              string `json:"direction"`
	PeriodSeconds          int    `json:"period_seconds"`
	BytesFloor             string `json:"bytes_floor"`
	PacketsFloor           string `json:"packets_floor"`
	GrowthBasisPoints      int    `json:"growth_basis_points"`
	VectorShareBasisPoints int    `json:"vector_share_basis_points"`
	MinObservedRecords     int    `json:"min_observed_records"`
	MinObservedAddresses   int    `json:"min_observed_addresses"`
}

type DDoSAssessment struct {
	ViewID    string                 `json:"view_id"`
	Version   string                 `json:"version"`
	Prefix    string                 `json:"prefix"`
	Direction string                 `json:"direction"`
	Before    DDoSWindowEvidence     `json:"before"`
	After     DDoSWindowEvidence     `json:"after"`
	Detection *anomaly.DDoSDetection `json:"detection,omitempty"`
}

type DDoSWindowEvidence struct {
	From              time.Time `json:"from"`
	To                time.Time `json:"to"`
	Source            string    `json:"source"`
	ResolutionSeconds int       `json:"resolution_seconds"`
	Bytes             string    `json:"bytes"`
	Packets           string    `json:"packets"`
	ObservedRecords   int       `json:"observed_records"`
	ObservedAddresses int       `json:"observed_addresses"`
	Sampled           bool      `json:"sampled"`
	Citation          string    `json:"citation"`
}

func (r DDoSAssessmentInput) Thresholds() anomaly.DDoSThresholds {
	return anomaly.DDoSThresholds{BytesFloor: r.BytesFloor, PacketsFloor: r.PacketsFloor, GrowthBasisPoints: r.GrowthBasisPoints,
		VectorShareBasisPoints: r.VectorShareBasisPoints, MinObservedRecords: r.MinObservedRecords, MinObservedAddresses: r.MinObservedAddresses}
}
