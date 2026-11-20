// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"math"
	"math/big"
	"net/netip"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func assessCapturedDDoS(ctx context.Context, capture *reportFlowCapture, settings ddosAssessmentSettings, windows anomaly.FlowFieldComparisonClocks, beforeIndex, afterIndex int, work int64) (flow.DDoSAssessment, error) {
	var empty flow.DDoSAssessment
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || capture == nil || tenant.String() != capture.TenantID {
		return empty, tenancy.ErrNoTenant
	}
	if capture.SourceGeneration < 1 || beforeIndex < 0 || afterIndex <= beforeIndex || afterIndex >= len(capture.Results) {
		return empty, anomaly.ErrDDoSCoverage
	}
	left, right := capture.Results[beforeIndex], capture.Results[afterIndex]
	if left.TenantID != capture.TenantID || right.TenantID != capture.TenantID {
		return empty, tenancy.ErrNoTenant
	}
	if left.Result.TagRevision != right.Result.TagRevision || !left.TagAsOf.Equal(right.TagAsOf) ||
		left.Result.RoleDigest != right.Result.RoleDigest || left.Result.RoutingProof != right.Result.RoutingProof ||
		!left.Result.Query.From.Equal(windows.Before.Start) || !left.Result.Query.To.Equal(windows.Before.End) ||
		!right.Result.Query.From.Equal(windows.After.Start) || !right.Result.Query.To.Equal(windows.After.End) {
		return empty, anomaly.ErrDDoSCoverage
	}
	authority, err := flowEvidenceAuthorityDigest(capture, settings.View, right)
	if err != nil {
		return empty, err
	}
	// The canonical prefix and direction are part of the cited evidence.
	digest := crypto.Hash([]byte(authority + "\x00" + settings.Target.String() + "\x00" + settings.Input.Direction))
	if len(digest) != 32 {
		return empty, anomaly.ErrDDoSCoverage
	}
	scope := hex.EncodeToString(digest)
	reference, before, err := projectDDoSWindow(ctx, left, settings, scope, work/4)
	if err != nil {
		return empty, err
	}
	current, after, err := projectDDoSWindow(ctx, right, settings, scope, work/4)
	if err != nil {
		return empty, err
	}
	finding, err := anomaly.EvaluateDDoS(ctx, reference, current, settings.Input.Thresholds(), work/2)
	if err != nil {
		return empty, err
	}
	finding, application, err := qualifyProjectedDDoS(ctx, reference, current, finding, settings.readApplication, settings.Input.Thresholds(), work/4)
	if err != nil {
		return empty, err
	}
	return flow.DDoSAssessment{ViewID: settings.View.ID, Version: settings.View.Version, Prefix: settings.Target.String(),
		Direction: settings.Input.Direction, Before: before, After: after, Detection: finding, Application: application}, ctx.Err()
}

func projectDDoSWindow(ctx context.Context, captured capturedReportFlow, settings ddosAssessmentSettings, scope string, memory int64) (anomaly.DDoSObservation, flow.DDoSWindowEvidence, error) {
	var none anomaly.DDoSObservation
	var empty flow.DDoSWindowEvidence
	result := captured.Result
	if captured.ID != settings.View.ID || captured.Version != settings.View.Version || scope == "" ||
		result.Source != "raw" || result.Coverage == nil || !result.Coverage.CompleteInputs || result.OldestInput.IsZero() ||
		result.Query.View != "table" || result.DetailLimited || result.Other != nil || result.ResolutionSeconds < 1 || result.ResolutionSeconds > settings.Input.PeriodSeconds ||
		len(result.Rows) == 0 || int64(len(result.Rows)) > memory/512 {
		return none, empty, anomaly.ErrDDoSCoverage
	}
	totals := ddosWindowTotals{addresses: make(map[netip.Addr]bool), services: make(map[string]*big.Int)}
	for _, row := range result.Rows {
		if err := ctx.Err(); err != nil {
			return none, empty, err
		}
		if err := totals.add(settings, row); err != nil {
			return none, empty, err
		}
	}
	citation := captured.ID + ":" + captured.Version + ":" + result.Query.To.UTC().Format(time.RFC3339Nano) + ":" + scope
	observed := anomaly.DDoSObservation{TenantID: captured.TenantID, Scope: scope, Target: settings.Target, Direction: settings.Input.Direction,
		From: result.Query.From, To: result.Query.To, Citation: citation, Complete: true,
		Bytes: totals.bytes.String(), Packets: totals.packets.String(), SYNOnlyPackets: totals.syn.String(), UDPPackets: totals.udp.String(),
		ApplicationBytes: totals.applicationBytes.String(), ApplicationPackets: totals.applicationPackets.String(),
		ObservedRecords: totals.records, ObservedAddresses: len(totals.addresses)}
	for service, packets := range totals.services {
		observed.Reflection = append(observed.Reflection, anomaly.ReflectionObservation{Service: service, Packets: packets.String()})
	}
	evidence := flow.DDoSWindowEvidence{From: observed.From, To: observed.To, Source: result.Source, ResolutionSeconds: result.ResolutionSeconds,
		Bytes: observed.Bytes, Packets: observed.Packets, ObservedRecords: observed.ObservedRecords, ObservedAddresses: observed.ObservedAddresses,
		Sampled: totals.sampled, Citation: observed.Citation}
	return observed, evidence, ctx.Err()
}

type ddosWindowTotals struct {
	bytes, packets, syn, udp             big.Int
	applicationBytes, applicationPackets big.Int
	records                              int
	sampled                              bool
	addresses                            map[netip.Addr]bool
	services                             map[string]*big.Int
}

func (total *ddosWindowTotals) add(settings ddosAssessmentSettings, row flowstore.PlanRow) error {
	protected, addrErr := netip.ParseAddr(row.Group[settings.SideField])
	sampling, sampleErr := strconv.ParseUint(row.Group["sampling"], 10, 64)
	records, countErr := strconv.Atoi(row.Metrics["flows:total"])
	bytes, bytesOK := ddosWindowCounter(row.Metrics["bytes:total"])
	packets, packetsOK := ddosWindowCounter(row.Metrics["packets:total"])
	if row.Other || addrErr != nil || !settings.Target.Contains(protected) || sampleErr != nil || sampling == 0 ||
		countErr != nil || records < 1 || records > math.MaxInt-total.records || !bytesOK || !packetsOK {
		return anomaly.ErrDDoSCoverage
	}
	protocol, found := row.Group["transport"]
	if !found {
		return anomaly.ErrDDoSCoverage
	}
	total.bytes.Add(&total.bytes, bytes)
	total.packets.Add(&total.packets, packets)
	total.records += records
	total.addresses[protected] = true
	total.sampled = total.sampled || sampling > 1
	switch protocol {
	case "tcp":
		flags, err := strconv.ParseUint(row.Group["tcp_flags"], 10, 8)
		if err != nil {
			return anomaly.ErrDDoSCoverage
		}
		if flags&2 != 0 && flags&0x15 == 0 {
			total.syn.Add(&total.syn, packets)
		} else if err := total.addApplicationFlow(settings.Input.Application, row.Group["dst_port"], bytes, packets); err != nil {
			return err
		}
	case "udp":
		port, err := strconv.ParseUint(row.Group["src_port"], 10, 16)
		if err != nil {
			return anomaly.ErrDDoSCoverage
		}
		total.udp.Add(&total.udp, packets)
		if service := reflectionService(port); service != "" {
			if total.services[service] == nil {
				total.services[service] = new(big.Int)
			}
			total.services[service].Add(total.services[service], packets)
		}
	}
	return nil
}

func (total *ddosWindowTotals) addApplicationFlow(binding *flow.DDoSApplicationBinding, destination string, bytes, packets *big.Int) error {
	if binding == nil {
		return nil
	}
	port, err := strconv.ParseUint(destination, 10, 16)
	if err != nil {
		return anomaly.ErrDDoSCoverage
	}
	if port == uint64(binding.Port) {
		total.applicationBytes.Add(&total.applicationBytes, bytes)
		total.applicationPackets.Add(&total.applicationPackets, packets)
	}
	return nil
}

func ddosWindowCounter(text string) (*big.Int, bool) {
	if len(text) == 0 || len(text) > 64 || text[0] < '0' || text[0] > '9' {
		return nil, false
	}
	value, ok := new(big.Int).SetString(text, 10)
	return value, ok
}

func reflectionService(port uint64) string {
	switch port {
	case 53:
		return "dns"
	case 123:
		return "ntp"
	case 11211:
		return "memcached"
	case 389:
		return "cldap"
	case 1900:
		return "ssdp"
	default:
		return ""
	}
}
