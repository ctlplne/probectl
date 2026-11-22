// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package anomaly

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrDDoSCoverage = errors.New("anomaly: complete comparable flow observations are required")

// ErrDDoSRecordSupport reports too few original flow records to support a decision.
var ErrDDoSRecordSupport = fmt.Errorf("%w: window has fewer original flow records than required", ErrDDoSCoverage)

// DDoSFastPeriod identifies the short observation windows used by the
// dedicated saved-rule evaluator. Legacy pressure windows retain their cadence.
func DDoSFastPeriod(seconds int) bool {
	return seconds == 5 || seconds == 10
}

func ValidDDoSPeriod(seconds int) bool {
	return DDoSFastPeriod(seconds) || seconds == 60 || seconds == 120 || seconds == 300
}

func DDoSCompletedWindows(at time.Time, seconds int) (FlowFieldComparisonClocks, error) {
	if at.IsZero() || !ValidDDoSPeriod(seconds) {
		return FlowFieldComparisonClocks{}, ErrDDoSCoverage
	}
	return completeFlowFieldPeriod(at.UTC(), FlowFieldPreviousWeek, time.Duration(seconds)*time.Second)
}

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

var ddosReflectionServices = map[uint64]string{
	53: "dns", 123: "ntp", 389: "cldap", 1900: "ssdp", 11211: "memcached",
}

var ddosReflectionServiceNames = slices.Collect(maps.Values(ddosReflectionServices))

// DDoSReflectionService is the supported service associated with a UDP source port.
func DDoSReflectionService(port uint64) string {
	return ddosReflectionServices[port]
}

// DDoSReflectionPorts lists the original UDP ports the detector distinguishes.
func DDoSReflectionPorts() []uint64 {
	return slices.Sorted(maps.Keys(ddosReflectionServices))
}

// DDoSObservation contains aggregate features derived from one completely
// admitted source window. Volume uses corrected counters and classifications
// retain an independent count of observed records.
type DDoSObservation struct {
	TenantID       string
	Scope          string
	Target         netip.Prefix
	Direction      string
	From, To       time.Time
	Citation       string
	Complete       bool
	Bytes          string
	Packets        string
	SYNOnlyPackets string
	UDPPackets     string
	// Older collector records can use zero for missing TCP flags or UDP source
	// ports. Their packets cannot establish a vector's historical absence.
	UnclassifiedTCPPackets string
	UnclassifiedUDPPackets string
	// Unknown transport contributes to the reference bound for either vector.
	UnclassifiedTransportPackets string
	ApplicationBytes             string
	ApplicationPackets           string
	// Traffic with missing port or transport evidence may belong to the bound listener.
	UnknownApplicationBytes   string
	UnknownApplicationPackets string
	ObservedRecords           int
	ObservedAddresses         int
	Reflection                []ReflectionObservation
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
	volumePressure := exceedsDDoSVolume(latest.bytes, earlier.bytes, bytesFloor, limits.GrowthBasisPoints) ||
		exceedsDDoSVolume(latest.packets, earlier.packets, packetsFloor, limits.GrowthBasisPoints)
	// Falling traffic in the rest of the protected population can hide a
	// growing vector. In that case the vector must clear the packet floor
	// on its own, in addition to the existing growth and share checks.
	var independentFloor *big.Rat
	if !volumePressure {
		independentFloor = packetsFloor
	}

	class, basis, confidence := DDoSVolumetric, "volume_growth", "tentative"
	var service, contributingPackets string
	reflectionService, reflectionPackets := growingDDoSReflection(earlier, latest, limits, independentFloor)
	switch {
	case qualifyingDDoSVectorSize(latest.syn, latest.packets, independentFloor, limits.VectorShareBasisPoints) &&
		growsDDoSVolume(latest.syn, earlier.possibleSYN, limits.GrowthBasisPoints):
		class, basis, confidence = DDoSSYN, "observed_tcp_flag_share", "corroborated"
		contributingPackets = latest.syn.Num().String()
	case reflectionService != "":
		class, service, basis = DDoSReflection, reflectionService, "observed_udp_service_port_share"
		contributingPackets = reflectionPackets.Num().String()
	case !volumePressure:
		outsidePressure, err := outsideDDoSApplicationPressure(&parser, reference, current, limits)
		if err != nil {
			return nil, err
		}
		if !outsidePressure {
			return nil, ctx.Err()
		}
	case current.Direction == "ingress" && current.Target.Bits() < current.Target.Addr().BitLen() &&
		current.ObservedAddresses >= limits.MinObservedAddresses && current.ObservedAddresses > reference.ObservedAddresses:
		class, basis, confidence = DDoSPrefixSpread, "observed_destination_spread", "corroborated"
	}
	if current.ObservedRecords < limits.MinObservedRecords {
		return nil, ErrDDoSRecordSupport
	}
	return &DDoSDetection{
		Class: class, Service: service, EvidenceBasis: basis, Confidence: confidence, ContributingPackets: contributingPackets,
		CurrentBytes: current.Bytes, CurrentPackets: current.Packets,
		ReferenceBytes: reference.Bytes, ReferencePackets: reference.Packets,
		CurrentCitation: current.Citation, ReferenceCitation: reference.Citation,
		ObservedRecords: current.ObservedRecords, ObservedAddresses: current.ObservedAddresses,
	}, ctx.Err()
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
	bytes, packets, syn *big.Rat
	possibleSYN         *big.Rat
	possibleReflection  *big.Rat
	reflected           map[string]*big.Rat
}

func parseDDoSCounts(parser *decimalSeasonalTraining, data DDoSObservation) (ddosCounts, error) {
	var result ddosCounts
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
	unclassifiedTCP, err := ddosCounter(parser, cmp.Or(data.UnclassifiedTCPPackets, "0"))
	if err != nil {
		return ddosCounts{}, err
	}
	unknownTransport, err := ddosCounter(parser, cmp.Or(data.UnclassifiedTransportPackets, "0"))
	if err != nil {
		return ddosCounts{}, err
	}
	result.possibleSYN = unclassifiedTCP.Add(unclassifiedTCP, result.syn)
	udp, err := ddosCounter(parser, data.UDPPackets)
	if err != nil || len(data.Reflection) > len(ddosReflectionServices) {
		return ddosCounts{}, ErrDDoSCoverage
	}
	// Missing transport can hide either vector, but the buckets must still
	// be disjoint when checking the observed packet total.
	result.possibleSYN.Add(result.possibleSYN, unknownTransport)
	if new(big.Rat).Add(result.possibleSYN, udp).Cmp(result.packets) > 0 {
		return ddosCounts{}, ErrDDoSCoverage
	}
	unclassifiedUDP, err := ddosCounter(parser, cmp.Or(data.UnclassifiedUDPPackets, "0"))
	if err != nil {
		return ddosCounts{}, ErrDDoSCoverage
	}
	if len(data.Reflection) > 0 {
		result.reflected = make(map[string]*big.Rat, len(data.Reflection))
	}
	total := new(big.Rat)
	for _, observation := range data.Reflection {
		if !slices.Contains(ddosReflectionServiceNames, observation.Service) {
			return ddosCounts{}, ErrDDoSCoverage
		}
		if result.reflected[observation.Service] != nil {
			return ddosCounts{}, ErrDDoSCoverage
		}
		value, err := ddosCounter(parser, observation.Packets)
		if err != nil {
			return ddosCounts{}, err
		}
		total.Add(total, value)
		result.reflected[observation.Service] = value
	}
	if total.Add(total, unclassifiedUDP).Cmp(udp) > 0 {
		return ddosCounts{}, ErrDDoSCoverage
	}
	result.possibleReflection = unclassifiedUDP.Add(unclassifiedUDP, unknownTransport)
	return result, nil
}

// A large share of current packets can be ordinary background. Compare each
// service against the same service in the original reference window.
func growingDDoSReflection(earlier, latest ddosCounts, limits DDoSThresholds, independentFloor *big.Rat) (string, *big.Rat) {
	var strongest *big.Rat
	var service string
	for name, packets := range latest.reflected {
		if !qualifyingDDoSVectorSize(packets, latest.packets, independentFloor, limits.VectorShareBasisPoints) {
			continue
		}
		before := earlier.possibleReflection
		if measured := earlier.reflected[name]; measured != nil {
			before = new(big.Rat).Add(before, measured)
		}
		if !growsDDoSVolume(packets, before, limits.GrowthBasisPoints) {
			continue
		}
		if strongest == nil || packets.Cmp(strongest) > 0 || (packets.Cmp(strongest) == 0 && name < service) {
			service, strongest = name, packets
		}
	}
	return service, strongest
}

func qualifyingDDoSVectorSize(packets, total, independentFloor *big.Rat, share int) bool {
	return (independentFloor == nil || packets.Cmp(independentFloor) >= 0) && hasDDoSShare(packets, total, share)
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
	return now.Cmp(floor) >= 0 && growsDDoSVolume(now, before, growth)
}

func growsDDoSVolume(now, before *big.Rat, growth int) bool {
	return now.Cmp(before) > 0 &&
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
