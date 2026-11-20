// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
)

type DDoSAssessmentInput struct {
	Version                string                  `json:"version"`
	Prefix                 string                  `json:"prefix"`
	Direction              string                  `json:"direction"`
	PeriodSeconds          int                     `json:"period_seconds"`
	BytesFloor             string                  `json:"bytes_floor"`
	PacketsFloor           string                  `json:"packets_floor"`
	GrowthBasisPoints      int                     `json:"growth_basis_points"`
	VectorShareBasisPoints int                     `json:"vector_share_basis_points"`
	MinObservedRecords     int                     `json:"min_observed_records"`
	MinObservedAddresses   int                     `json:"min_observed_addresses"`
	Application            *DDoSApplicationBinding `json:"application,omitempty"`
}

type DDoSApplicationBinding struct {
	Service string `json:"service"`
	Port    uint16 `json:"port"`
}

type DDoSAssessment struct {
	ViewID      string                           `json:"view_id"`
	Version     string                           `json:"version"`
	Prefix      string                           `json:"prefix"`
	Direction   string                           `json:"direction"`
	Before      DDoSWindowEvidence               `json:"before"`
	After       DDoSWindowEvidence               `json:"after"`
	Detection   *anomaly.DDoSDetection           `json:"detection,omitempty"`
	Application *anomaly.DDoSApplicationEvidence `json:"application,omitempty"`
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

// ValidatedPrefix checks the detector configuration and resolves its canonical network.
func (r DDoSAssessmentInput) ValidatedPrefix() (netip.Prefix, error) {
	target, err := netip.ParsePrefix(r.Prefix)
	if err != nil || target != target.Masked() || target.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("the protected prefix must be a canonical IPv4 or IPv6 prefix")
	}
	if _, err := QueryViewVersion(r.Version); err != nil {
		return netip.Prefix{}, errors.New("the assessment needs an exact saved flow view revision")
	}
	if r.Direction != "ingress" && r.Direction != "egress" {
		return netip.Prefix{}, errors.New("select the observed ingress or egress direction")
	}
	if !anomaly.ValidDDoSPeriod(r.PeriodSeconds) {
		return netip.Prefix{}, errors.New("assessment windows must be 5, 10, 60, 120 or 300 seconds")
	}
	if app := r.Application; app != nil {
		if r.Direction != "ingress" || !target.IsSingleIP() || app.Port == 0 ||
			app.Service == "" || len(app.Service) > 128 || strings.TrimSpace(app.Service) != app.Service {
			return netip.Prefix{}, errors.New("application context requires an exact ingress host, an HTTP service and a positive port")
		}
	}
	if err := r.Thresholds().Validate(); err != nil {
		return netip.Prefix{}, errors.New("set positive traffic and coverage floors and a valid growth and vector share")
	}
	return target, nil
}
