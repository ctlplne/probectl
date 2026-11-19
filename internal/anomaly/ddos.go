// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"context"
	"errors"
	"math/big"
	"net/netip"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrDDoSCoverage = errors.New("anomaly: complete comparable flow observations are required")

type DDoSClass string

const (
	DDoSSYN          DDoSClass = "tcp_syn_pressure"
	DDoSReflection   DDoSClass = "udp_reflection_suspected"
	DDoSPrefixSpread DDoSClass = "distributed_destination_pressure"
	DDoSVolumetric   DDoSClass = "volumetric_pressure"
)

// Reflection is an observed service-port association. Flow records alone
// cannot establish that a request was spoofed.
type ReflectionObservation struct {
	Service string `json:"service"`
	Packets string `json:"packets"`
}

// DDoSObservation contains aggregate features derived from one completely
// admitted source window. Volume uses corrected counters and classifications
// retain an independent count of observed records.
type DDoSObservation struct {
	TenantID          string
	Scope             string
	Target            netip.Prefix
	Direction         string
	From, To          time.Time
	Citation          string
	Complete          bool
	Bytes             string
	Packets           string
	SYNOnlyPackets    string
	UDPPackets        string
	ObservedRecords   int
	ObservedAddresses int
	Reflection        []ReflectionObservation
}

type DDoSThresholds struct {
	BytesFloor             string
	PacketsFloor           string
	GrowthBasisPoints      int
	VectorShareBasisPoints int
	MinObservedRecords     int
	MinObservedAddresses   int
}

// Validate checks that configuration supplies bounded input and coverage floors.
func (settings DDoSThresholds) Validate() error {
	if settings.GrowthBasisPoints < 1 || settings.GrowthBasisPoints > 1000000 ||
		settings.VectorShareBasisPoints < 1 || settings.VectorShareBasisPoints > 10000 ||
		settings.MinObservedRecords < 1 || settings.MinObservedAddresses < 2 {
		return ErrDDoSCoverage
	}
	parser := decimalSeasonalTraining{work: 8192}
	for _, floor := range []string{settings.BytesFloor, settings.PacketsFloor} {
		value, err := ddosCounter(&parser, floor)
		if err != nil || value.Sign() <= 0 {
			return ErrDDoSCoverage
		}
	}
	return nil
}

type DDoSDetection struct {
	Class               DDoSClass `json:"class"`
	Service             string    `json:"service,omitempty"`
	EvidenceBasis       string    `json:"evidence_basis"`
	Confidence          string    `json:"confidence"`
	ContributingPackets string    `json:"contributing_packets,omitempty"`
	CurrentBytes        string    `json:"current_bytes"`
	CurrentPackets      string    `json:"current_packets"`
	ReferenceBytes      string    `json:"reference_bytes"`
	ReferencePackets    string    `json:"reference_packets"`
	ObservedRecords     int       `json:"observed_records"`
	ObservedAddresses   int       `json:"observed_addresses"`
	ReferenceCitation   string    `json:"reference_citation"`
	CurrentCitation     string    `json:"current_citation"`
}

// EvaluateDDoS assesses passive flow observations from one protected
// population. The caller retains publication admission and incident state.
func EvaluateDDoS(ctx context.Context, reference, current DDoSObservation, limits DDoSThresholds, work int64) (*DDoSDetection, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil, ErrNoTenant
	}
	if reference.TenantID != tenant.String() || current.TenantID != tenant.String() {
		return nil, ErrCrossTenantFeature
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if err := checkDDoSWindows(ctx, reference, current); err != nil {
		return nil, err
	}
	parser := decimalSeasonalTraining{work: work}
	earlier, err := parseDDoSCounts(&parser, reference)
	if err != nil {
		return nil, err
	}
	latest, err := parseDDoSCounts(&parser, current)
	if err != nil {
		return nil, err
	}
	bytesFloor, err := ddosCounter(&parser, limits.BytesFloor)
	if err != nil {
		return nil, err
	}
	packetsFloor, err := ddosCounter(&parser, limits.PacketsFloor)
	if err != nil {
		return nil, err
	}
	if bytesFloor.Sign() <= 0 || packetsFloor.Sign() <= 0 {
		return nil, ErrDDoSCoverage
	}
	if current.ObservedRecords < limits.MinObservedRecords ||
		!exceedsDDoSVolume(latest.bytes, earlier.bytes, bytesFloor, limits.GrowthBasisPoints) &&
			!exceedsDDoSVolume(latest.packets, earlier.packets, packetsFloor, limits.GrowthBasisPoints) {
		return nil, ctx.Err()
	}

	result := &DDoSDetection{
		Class: DDoSVolumetric, EvidenceBasis: "volume_growth", Confidence: "tentative",
		CurrentBytes: current.Bytes, CurrentPackets: current.Packets,
		ReferenceBytes: reference.Bytes, ReferencePackets: reference.Packets,
		CurrentCitation: current.Citation, ReferenceCitation: reference.Citation,
		ObservedRecords: current.ObservedRecords, ObservedAddresses: current.ObservedAddresses,
	}
	switch {
	case hasDDoSShare(latest.syn, latest.packets, limits.VectorShareBasisPoints):
		result.Class, result.EvidenceBasis, result.Confidence = DDoSSYN, "observed_tcp_flag_share", "corroborated"
		result.ContributingPackets = latest.syn.Num().String()
	case hasDDoSShare(latest.reflected, latest.packets, limits.VectorShareBasisPoints):
		result.Class, result.Service, result.EvidenceBasis = DDoSReflection, latest.service, "observed_udp_service_port_share"
		result.ContributingPackets = latest.reflected.Num().String()
	case current.Direction == "ingress" && current.Target.Bits() < current.Target.Addr().BitLen() &&
		current.ObservedAddresses >= limits.MinObservedAddresses && current.ObservedAddresses > reference.ObservedAddresses:
		result.Class, result.EvidenceBasis, result.Confidence = DDoSPrefixSpread, "observed_destination_spread", "corroborated"
	}
	return result, ctx.Err()
}

func checkDDoSWindows(ctx context.Context, reference, current DDoSObservation) error {
	if !reference.Complete || !current.Complete || reference.Scope == "" || len(reference.Scope) > 128 || reference.Scope != current.Scope ||
		reference.Target != current.Target || !current.Target.IsValid() || current.Target != current.Target.Masked() ||
		reference.Direction != current.Direction || (current.Direction != "ingress" && current.Direction != "egress") ||
		reference.From.IsZero() || !reference.From.Before(reference.To) || reference.To.After(current.From) ||
		!current.From.Before(current.To) || reference.To.Sub(reference.From) != current.To.Sub(current.From) ||
		reference.Citation == "" || current.Citation == "" || len(reference.Citation) > 512 || len(current.Citation) > 512 ||
		reference.ObservedRecords < 0 || current.ObservedRecords < 0 ||
		reference.ObservedAddresses < 0 || current.ObservedAddresses < 0 ||
		reference.ObservedAddresses > reference.ObservedRecords || current.ObservedAddresses > current.ObservedRecords {
		return ErrDDoSCoverage
	}
	return ctx.Err()
}

type ddosCounts struct {
	bytes, packets, syn, reflected *big.Rat
	service                        string
}

func parseDDoSCounts(parser *decimalSeasonalTraining, data DDoSObservation) (ddosCounts, error) {
	result := ddosCounts{reflected: new(big.Rat)}
	var err error
	if result.bytes, err = ddosCounter(parser, data.Bytes); err != nil {
		return ddosCounts{}, err
	}
	if result.packets, err = ddosCounter(parser, data.Packets); err != nil {
		return ddosCounts{}, err
	}
	if data.ObservedRecords == 0 && (result.bytes.Sign() > 0 || result.packets.Sign() > 0) {
		return ddosCounts{}, ErrDDoSCoverage
	}
	if result.syn, err = ddosCounter(parser, data.SYNOnlyPackets); err != nil {
		return ddosCounts{}, err
	}
	udp, err := ddosCounter(parser, data.UDPPackets)
	if err != nil || new(big.Rat).Add(result.syn, udp).Cmp(result.packets) > 0 || len(data.Reflection) > 5 {
		return ddosCounts{}, ErrDDoSCoverage
	}
	seen := make(map[string]bool, len(data.Reflection))
	total := new(big.Rat)
	for _, observation := range data.Reflection {
		switch observation.Service {
		case "dns", "ntp", "memcached", "cldap", "ssdp":
		default:
			return ddosCounts{}, ErrDDoSCoverage
		}
		if seen[observation.Service] {
			return ddosCounts{}, ErrDDoSCoverage
		}
		seen[observation.Service] = true
		value, err := ddosCounter(parser, observation.Packets)
		if err != nil {
			return ddosCounts{}, err
		}
		total.Add(total, value)
		if comparison := value.Cmp(result.reflected); comparison > 0 || (comparison == 0 && observation.Service < result.service) {
			result.reflected, result.service = value, observation.Service
		}
	}
	if total.Cmp(udp) > 0 {
		return ddosCounts{}, ErrDDoSCoverage
	}
	return result, nil
}

func ddosCounter(parser *decimalSeasonalTraining, text string) (*big.Rat, error) {
	if len(text) > 64 || strings.IndexFunc(text, func(digit rune) bool { return digit < '0' || digit > '9' }) >= 0 {
		return nil, ErrDDoSCoverage
	}
	value, err := parser.parse(text)
	if err != nil || value.Sign() < 0 || !value.IsInt() {
		return nil, ErrDDoSCoverage
	}
	return value, nil
}

func exceedsDDoSVolume(now, before, floor *big.Rat, growth int) bool {
	return now.Cmp(floor) >= 0 && now.Cmp(before) > 0 &&
		hasDDoSShare(new(big.Rat).Sub(now, before), before, growth)
}

func hasDDoSShare(matched, population *big.Rat, basisPoints int) bool {
	if matched.Sign() <= 0 {
		return false
	}
	left := new(big.Rat).Mul(matched, big.NewRat(10000, 1))
	right := new(big.Rat).Mul(population, big.NewRat(int64(basisPoints), 1))
	return left.Cmp(right) >= 0
}
