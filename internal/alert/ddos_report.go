// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"math/big"
	"net/netip"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/flow"
)

// DDoSReport describes the completed windows captured for one incident.
// Rates are window averages and the source totals remain in exact decimal form.
type DDoSReport struct {
	IncidentID      string               `json:"incident_id"`
	EpisodeID       string               `json:"episode_id"`
	Prefix          string               `json:"prefix"`
	Direction       string               `json:"direction"`
	From            time.Time            `json:"from"`
	To              time.Time            `json:"to"`
	ObservedSeconds int64                `json:"observed_seconds"`
	Windows         [2]DDoSReportWindow  `json:"windows"`
	PeakBitRate     DDoSReportRate       `json:"peak_bit_rate"`
	PeakPacketRate  DDoSReportRate       `json:"peak_packet_rate"`
	TopSources      []DDoSReportSource   `json:"top_sources"`
	ActionsVisible  bool                 `json:"actions_visible"`
	Actions         []DDoSReportDecision `json:"actions,omitempty"`
}

type DDoSReportSource struct {
	Address string `json:"address"`
	Bytes   string `json:"bytes"`
	Packets string `json:"packets"`
}

type DDoSReportDecision struct {
	ProposalID string     `json:"proposal_id"`
	Kind       string     `json:"kind"`
	State      string     `json:"state"`
	CreatedAt  time.Time  `json:"created_at"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
}

type DDoSReportWindow struct {
	Evidence   flow.DDoSWindowEvidence `json:"evidence"`
	Vector     anomaly.DDoSClass       `json:"vector"`
	Service    string                  `json:"service,omitempty"`
	Confidence string                  `json:"confidence"`
}

type DDoSReportRate struct {
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Count     string    `json:"count"`
	Seconds   int64     `json:"seconds"`
	PerSecond string    `json:"per_second"`
}

// SummarizeDDoSReport takes the already authorized, server-owned episode
// receipt. It keeps traffic totals, timestamps and vector citations together.
func SummarizeDDoSReport(receipt DDoSEvaluationEvidence) (DDoSReport, error) {
	previous, current := receipt.Previous, receipt.Current
	prefix, err := netip.ParsePrefix(current.Prefix)
	width := current.After.To.Sub(current.After.From)
	if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || previous.Prefix != current.Prefix ||
		previous.Direction != current.Direction || (current.Direction != "ingress" && current.Direction != "egress") ||
		receipt.IncidentID == "" || receipt.EpisodeID == "" || previous.ViewID == "" || previous.ViewID != current.ViewID ||
		previous.Version != current.Version || !previous.After.To.Equal(current.After.From) ||
		previous.After.To.Sub(previous.After.From) != width || (width != time.Minute && width != 2*time.Minute && width != 5*time.Minute) {
		return DDoSReport{}, anomaly.ErrDDoSCoverage
	}
	out := DDoSReport{
		IncidentID: receipt.IncidentID, EpisodeID: receipt.EpisodeID, Prefix: current.Prefix, Direction: current.Direction,
		From: previous.After.From.UTC(), To: current.After.To.UTC(), ObservedSeconds: int64((2 * width) / time.Second),
	}
	var peakBits, peakPackets *big.Int
	for i, assessment := range [2]flow.DDoSAssessment{previous, current} {
		window, detector := assessment.After, assessment.Detection
		bits, bitsOK := ddosReportCount(window.Bytes)
		packets, packetsOK := ddosReportCount(window.Packets)
		if window.Source != "raw" || window.Citation == "" || !bitsOK || !packetsOK || detector == nil ||
			detector.CurrentCitation != window.Citation || detector.CurrentBytes != window.Bytes || detector.CurrentPackets != window.Packets {
			return DDoSReport{}, anomaly.ErrDDoSCoverage
		}
		window.From, window.To = window.From.UTC(), window.To.UTC()
		out.Windows[i] = DDoSReportWindow{Evidence: window, Vector: detector.Class, Service: detector.Service, Confidence: detector.Confidence}
		bits.Lsh(bits, 3)
		if peakBits == nil || bits.Cmp(peakBits) > 0 {
			peakBits = bits
			out.PeakBitRate = ddosReportRate(window, bits, int64(width/time.Second))
		}
		if peakPackets == nil || packets.Cmp(peakPackets) > 0 {
			peakPackets = packets
			out.PeakPacketRate = ddosReportRate(window, packets, int64(width/time.Second))
		}
	}
	return out, nil
}

func ddosReportCount(raw string) (*big.Int, bool) {
	if len(raw) == 0 || len(raw) > 64 || strings.IndexFunc(raw, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return nil, false
	}
	return new(big.Int).SetString(raw, 10)
}

func ddosReportRate(window flow.DDoSWindowEvidence, count *big.Int, seconds int64) DDoSReportRate {
	rate := new(big.Rat).SetFrac(count, big.NewInt(seconds))
	return DDoSReportRate{
		From: window.From, To: window.To, Count: count.String(), Seconds: seconds,
		PerSecond: rate.FloatString(3),
	}
}
