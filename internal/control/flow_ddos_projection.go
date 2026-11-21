// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/big"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	errDDoSTimingCoverage   = fmt.Errorf("%w: original reports do not independently support the short-window decision", anomaly.ErrDDoSCoverage)
	errDDoSExporterCoverage = fmt.Errorf("%w: a required exporter was unobserved", anomaly.ErrDDoSCoverage)
	errDDoSExporterSampling = fmt.Errorf("%w: the reported sampling rate sets differ", anomaly.ErrDDoSCoverage)
	errDDoSSampleCoverage   = fmt.Errorf("%w: a sampling group contains too few original flow records", anomaly.ErrDDoSCoverage)
	errDDoSTrendCoverage    = fmt.Errorf("%w: volume follows a weekly trend without independent corroboration", anomaly.ErrDDoSCoverage)
	errDDoSCounterIntegrity = fmt.Errorf("%w: corrected flow counters disagree with their original evidence", anomaly.ErrDDoSCoverage)
)

type ddosExporterRate struct {
	exporter, rate string
}

type ddosProjectedWindow struct {
	observation   anomaly.DDoSObservation
	evidence      flow.DDoSWindowEvidence
	samplingRates map[ddosExporterRate]struct{}
}

func assessMatchedDDoS(ctx context.Context, capture *reportFlowCapture, settings ddosAssessmentSettings, match ddosMatchedWindow, work int64) (flow.DDoSAssessment, error) {
	assessment, err := assessCapturedDDoS(ctx, capture, settings, match.clocks, match.beforeIndex, match.afterIndex, work)
	if err == nil && match.volumeFollowsTrend && assessment.Detection != nil {
		// A growing destination count describes the same flow population as
		// the volume increase. It cannot corroborate a continuing trend.
		switch assessment.Detection.Class {
		case anomaly.DDoSVolumetric, anomaly.DDoSPrefixSpread:
			return flow.DDoSAssessment{}, errDDoSTrendCoverage
		}
	}
	return assessment, err
}

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
	scope, err := ddosCaptureScope(capture, settings, right)
	if err != nil {
		return empty, err
	}
	before, err := projectDDoSWindow(ctx, left, settings, scope, work/4)
	if err != nil {
		return empty, err
	}
	after, err := projectDDoSWindow(ctx, right, settings, scope, work/4)
	if err != nil {
		return empty, err
	}
	// Cited reads reconstruct an already admitted receipt at its original clocks.
	if !settings.Cited && !maps.Equal(before.samplingRates, after.samplingRates) {
		return empty, errDDoSExporterSampling
	}
	reference, current := before.observation, after.observation
	finding, err := anomaly.EvaluateDDoS(ctx, reference, current, settings.Input.Thresholds(), work/2)
	if err != nil {
		return empty, err
	}
	finding, application, err := qualifyProjectedDDoS(ctx, reference, current, finding, settings.readApplication, settings.Input.Thresholds(), work/4)
	if err != nil {
		return empty, err
	}
	if err := checkDDoSTimingEvidence(ctx, right, settings, scope, before, finding, application, work/4); err != nil {
		return empty, err
	}
	return flow.DDoSAssessment{ViewID: settings.View.ID, Version: settings.View.Version, Prefix: settings.Target.String(),
		Direction: settings.Input.Direction, ReferenceMode: settings.Input.ReferenceMode, Before: before.evidence, After: after.evidence, Detection: finding, Application: application}, ctx.Err()
}

func checkDDoSTimingEvidence(ctx context.Context, captured capturedReportFlow, settings ddosAssessmentSettings, scope string,
	reference ddosProjectedWindow, finding *anomaly.DDoSDetection, application *anomaly.DDoSApplicationEvidence, work int64) error {
	// Cited reads reconstruct the already admitted receipt. New detection
	// policy applies during prospective assessment and episode admission.
	if settings.Cited || !anomaly.DDoSFastPeriod(settings.Input.PeriodSeconds) ||
		!slices.ContainsFunc(captured.Result.Rows, func(row flowstore.PlanRow) bool { return row.CrossesWindowStart }) {
		return ctx.Err()
	}
	// Keep the reference's end-clock counters. The contained reports must
	// support the current decision, including quiet coverage after an episode.
	current, err := projectDDoSWindowRows(ctx, captured, settings, scope, work, true)
	if errors.Is(err, anomaly.ErrDDoSCoverage) {
		return errDDoSTimingCoverage
	}
	if err != nil {
		return err
	}
	if current.observation.ObservedRecords == 0 || !maps.Equal(reference.samplingRates, current.samplingRates) {
		return errDDoSTimingCoverage
	}
	if finding == nil {
		return ctx.Err()
	}
	limits := settings.Input.Thresholds()
	confirmed, err := anomaly.EvaluateDDoS(ctx, reference.observation, current.observation, limits, work)
	if errors.Is(err, anomaly.ErrDDoSRecordSupport) {
		return errDDoSTimingCoverage
	}
	if err != nil {
		return err
	}
	if confirmed == nil || confirmed.Class != finding.Class || confirmed.Service != finding.Service {
		return errDDoSTimingCoverage
	}
	if application != nil {
		confirmed, timedApplication, err := anomaly.QualifyDDoSApplication(ctx, reference.observation, current.observation, application.Reference, application.Current, confirmed, limits, work)
		if err != nil {
			return err
		}
		if confirmed == nil || timedApplication == nil || timedApplication.State != application.State {
			return errDDoSTimingCoverage
		}
	}
	return ctx.Err()
}

func ddosCaptureScope(capture *reportFlowCapture, settings ddosAssessmentSettings, result capturedReportFlow) (string, error) {
	authority, err := flowEvidenceAuthorityDigest(capture, settings.View, result)
	if err != nil {
		return "", err
	}
	// Include the selected exporter set in scoped citations. Keep citations
	// for existing rules stable when no exporter set was configured.
	material := authority + "\x00" + settings.Target.String() + "\x00" + settings.Input.Direction
	if len(settings.Input.RequiredExporters) != 0 {
		material += "\x00" + strings.Join(settings.Input.RequiredExporters, "\x00")
	}
	digest := crypto.Hash([]byte(material))
	if len(digest) != 32 {
		return "", anomaly.ErrDDoSCoverage
	}
	return hex.EncodeToString(digest), nil
}

func projectDDoSWindow(ctx context.Context, captured capturedReportFlow, settings ddosAssessmentSettings, scope string, memory int64) (ddosProjectedWindow, error) {
	return projectDDoSWindowRows(ctx, captured, settings, scope, memory, false)
}

func projectDDoSWindowRows(ctx context.Context, captured capturedReportFlow, settings ddosAssessmentSettings, scope string, memory int64,
	excludeCrossing bool) (ddosProjectedWindow, error) {
	var empty ddosProjectedWindow
	result := captured.Result
	if captured.ID != settings.View.ID || captured.Version != settings.View.Version || scope == "" ||
		result.Source != "raw" || result.Coverage == nil || !result.Coverage.CompleteInputs || result.OldestInput.IsZero() ||
		result.Query.View != "table" || result.DetailLimited || result.Other != nil || result.ResolutionSeconds < 1 || result.ResolutionSeconds > settings.Input.PeriodSeconds ||
		len(result.Rows) == 0 || int64(len(result.Rows)) > memory/512 {
		return empty, anomaly.ErrDDoSCoverage
	}
	totals := ddosWindowTotals{addresses: make(map[netip.Addr]bool), services: make(map[string]*big.Int)}
	required := settings.Input.RequiredExporters
	observedExporters := make(map[string]bool, len(required))
	var samplingRates map[ddosExporterRate]struct{}
	if len(required) != 0 || (!settings.Cited && anomaly.DDoSFastPeriod(settings.Input.PeriodSeconds)) {
		samplingRates = make(map[ddosExporterRate]struct{}, len(required))
	}
	for _, row := range result.Rows {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if !settings.Cited && row.InvalidSamplingCounters {
			return empty, errDDoSCounterIntegrity
		}
		if excludeCrossing && row.CrossesWindowStart {
			continue
		}
		if err := totals.add(settings, row); err != nil {
			return empty, err
		}
		var exporter string
		if len(required) != 0 {
			exporter = row.Group["exporter"]
			if !slices.Contains(required, exporter) {
				return empty, errDDoSExporterCoverage
			}
			observedExporters[exporter] = true
		}
		if samplingRates != nil {
			samplingRates[ddosExporterRate{exporter: exporter, rate: row.Group["sampling"]}] = struct{}{}
		}
	}
	if len(observedExporters) != len(required) {
		return empty, errDDoSExporterCoverage
	}
	// Records from other sampling rates cannot support this estimate. When
	// exporters are required, each named exporter supplies its own evidence.
	for _, records := range totals.sampledRecords {
		if records < settings.Input.MinObservedRecords {
			return empty, errDDoSSampleCoverage
		}
	}
	citation := captured.ID + ":" + captured.Version + ":" + result.Query.To.UTC().Format(time.RFC3339Nano) + ":" + scope
	observed := anomaly.DDoSObservation{TenantID: captured.TenantID, Scope: scope, Target: settings.Target, Direction: settings.Input.Direction,
		From: result.Query.From, To: result.Query.To, Citation: citation, Complete: true,
		Bytes: totals.bytes.String(), Packets: totals.packets.String(), SYNOnlyPackets: totals.syn.String(), UDPPackets: totals.udp.String(),
		UnclassifiedTCPPackets: totals.unclassifiedTCP.String(), UnclassifiedUDPPackets: totals.unclassifiedUDP.String(),
		ApplicationBytes: totals.applicationBytes.String(), ApplicationPackets: totals.applicationPackets.String(),
		ObservedRecords: totals.records, ObservedAddresses: len(totals.addresses)}
	for service, packets := range totals.services {
		observed.Reflection = append(observed.Reflection, anomaly.ReflectionObservation{Service: service, Packets: packets.String()})
	}
	evidence := flow.DDoSWindowEvidence{From: observed.From, To: observed.To, Source: result.Source, ResolutionSeconds: result.ResolutionSeconds,
		Bytes: observed.Bytes, Packets: observed.Packets, ObservedRecords: observed.ObservedRecords, ObservedAddresses: observed.ObservedAddresses,
		ObservedExporters: len(observedExporters), Sampled: totals.sampled, Citation: observed.Citation}
	return ddosProjectedWindow{observation: observed, evidence: evidence, samplingRates: samplingRates}, ctx.Err()
}

type ddosWindowTotals struct {
	bytes, packets, syn, udp             big.Int
	unclassifiedTCP, unclassifiedUDP     big.Int
	applicationBytes, applicationPackets big.Int
	records                              int
	sampled                              bool
	sampledRecords                       map[ddosExporterRate]int
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
	if sampling > 1 {
		total.sampled = true
		if !settings.Cited {
			key := ddosExporterRate{rate: row.Group["sampling"]}
			if len(settings.Input.RequiredExporters) != 0 {
				key.exporter = row.Group["exporter"]
			}
			if total.sampledRecords == nil {
				total.sampledRecords = make(map[ddosExporterRate]int)
			}
			total.sampledRecords[key] += records
		}
	}
	switch protocol {
	case "tcp":
		flags, err := strconv.ParseUint(row.Group["tcp_flags"], 10, 8)
		if err != nil {
			return anomaly.ErrDDoSCoverage
		}
		if flags == 0 {
			total.unclassifiedTCP.Add(&total.unclassifiedTCP, packets)
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
		if port == 0 {
			total.unclassifiedUDP.Add(&total.unclassifiedUDP, packets)
		}
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
