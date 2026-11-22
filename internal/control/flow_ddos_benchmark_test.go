// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	benchmarkDDoSTenant = "25ebf92b-c387-451d-9e67-0b323c402a58"
	benchmarkDDoSView   = "548baa36-4c4a-47a1-b7d8-7c7f48d36716"
	benchmarkDDoSRule   = "18df565b-2523-443a-b139-eab57d6c0f79"
	benchmarkDDoSWork   = 1 << 20
	benchmarkDDoSVars   = 16
)

var benchmarkDDoSEpoch = time.Date(2026, 1, 12, 12, 0, 0, 0, time.UTC)

// The fixture describes offline aggregate observations and manually labeled
// synthetic scenarios. It contains no traffic generator or endpoint operation.
type benchmarkDDoSWindow struct {
	Profile                      string
	Bytes, Packets               int
	Records, Addresses, Sampling int
	OtherBytes, OtherPackets     int
	Complete                     bool
	Application                  benchmarkDDoSApplication
}

type benchmarkDDoSApplication struct {
	Requests, Failures, LatencyMS int
	WrongHost                     bool
}

type benchmarkDDoSTrial struct {
	Name, Family       string
	OnsetBeforeAligned int
	Settings           flow.DDoSAssessmentInput
	Reference          benchmarkDDoSWindow
	Windows            [2]benchmarkDDoSWindow
}

type benchmarkDDoSLabel struct {
	Positive     bool
	Class        anomaly.DDoSClass
	Service      string
	Residual     bool
	Abstained    bool
	DemandProven bool
}

func benchmarkDDoSLabels() map[string]benchmarkDDoSLabel {
	return map[string]benchmarkDDoSLabel{
		"volume_health_drop":            {Positive: true, Class: anomaly.DDoSVolumetric},
		"sampled_volume_health_drop":    {Positive: true, Abstained: true},
		"tcp_syn":                       {Positive: true, Class: anomaly.DDoSSYN},
		"udp_dns":                       {Positive: true, Class: anomaly.DDoSReflection, Service: "dns"},
		"udp_ntp":                       {Positive: true, Class: anomaly.DDoSReflection, Service: "ntp"},
		"udp_cldap":                     {Positive: true, Class: anomaly.DDoSReflection, Service: "cldap"},
		"udp_ssdp":                      {Positive: true, Class: anomaly.DDoSReflection, Service: "ssdp"},
		"udp_memcached":                 {Positive: true, Class: anomaly.DDoSReflection, Service: "memcached"},
		"distributed_destination":       {Positive: true, Class: anomaly.DDoSPrefixSpread},
		"rotating_network_vectors":      {Positive: true, Class: anomaly.DDoSReflection, Service: "dns"},
		"volume_healthy_steady_app":     {Positive: true, Class: anomaly.DDoSVolumetric},
		"low_intensity":                 {Positive: true},
		"partial_flow_attack":           {Positive: true, Abstained: true},
		"unavailable_app_attack":        {Positive: true, Abstained: true},
		"attack_amid_healthy_growth":    {Positive: true, Abstained: true},
		"crowd_with_unrelated_pressure": {Positive: true, Class: anomaly.DDoSVolumetric, Residual: true},
		"matched_totals_unrelated_port": {Positive: true, Class: anomaly.DDoSVolumetric, Residual: true},
		"matched_flash_crowd":           {DemandProven: true},
		"stable":                        {},
		"single_window":                 {},
		"below_observation_floor":       {Abstained: true},
		"inconsistent_pressure":         {},
		"partial_flow_benign":           {Abstained: true},
		"app_for_another_host":          {Abstained: true},
		"insufficient_app_reference":    {Abstained: true},
		"flash_crowd_packet_mix":        {Abstained: true},
	}
}

func benchmarkDDoSFixture() []benchmarkDDoSTrial {
	var trials []benchmarkDDoSTrial
	for variation := range benchmarkDDoSVars {
		input := flow.DDoSAssessmentInput{Version: "7", Prefix: "192.0.2.0/24", Direction: "ingress", PeriodSeconds: 5,
			BytesFloor: "200000", PacketsFloor: "2500", GrowthBasisPoints: 2000, VectorShareBasisPoints: 6000,
			MinObservedRecords: 50, MinObservedAddresses: 8}
		appInput := input
		appInput.Prefix = "192.0.2.1/32"
		appInput.Application = &flow.DDoSApplicationBinding{Service: "synthetic-public-site", Port: 443}
		ref := benchmarkDDoSWindow{Profile: "ordinary", Bytes: 90000 + 761*variation, Packets: 900 + 13*variation,
			Records: 64 + variation, Addresses: 1, Sampling: 1, Complete: true,
			Application: benchmarkDDoSApplication{Requests: 24 + variation, LatencyMS: 16 + variation%7}}
		volume := ref
		volume.Bytes, volume.Packets = 4*ref.Bytes, 4*ref.Packets
		syn, spread, mild, few := volume, volume, ref, volume
		syn.Profile, spread.Addresses, few.Records = "syn", 12+variation, 15+variation
		mild.Bytes, mild.Packets = ref.Bytes*17/10, ref.Packets*17/10
		degraded, flash, sampled := volume, volume, volume
		degraded.Application.Failures = 8 + variation
		degraded.Application.LatencyMS = 65 + variation
		flash.Application.Requests *= 4
		sampled.Application, sampled.Sampling = degraded.Application, 4+11*variation
		crowdWithOtherPacketMix := flash
		crowdWithOtherPacketMix.Packets += ref.Packets*3 + variation
		missingFlow, missingApp, foreignApp, weakReference := degraded, degraded, flash, ref
		missingFlow.Complete, missingApp.Application.Requests = false, 0
		foreignApp.Application.WrongHost = true
		weakReference.Application.Requests = 1 + variation
		add := func(family string, config flow.DDoSAssessmentInput, reference, first, second benchmarkDDoSWindow) {
			trials = append(trials, benchmarkDDoSTrial{Name: fmt.Sprintf("%s/%02d", family, variation), Family: family,
				OnsetBeforeAligned: variation % config.PeriodSeconds, Settings: config, Reference: reference, Windows: [2]benchmarkDDoSWindow{first, second}})
		}
		add("volume_health_drop", appInput, ref, degraded, degraded)
		add("sampled_volume_health_drop", appInput, ref, sampled, sampled)
		add("tcp_syn", input, ref, syn, syn)
		for _, service := range []string{"dns", "ntp", "cldap", "ssdp", "memcached"} {
			udp := volume
			udp.Profile = service
			add("udp_"+service, input, ref, udp, udp)
		}
		add("distributed_destination", input, ref, spread, spread)
		dns := volume
		dns.Profile = "dns"
		add("rotating_network_vectors", input, ref, syn, dns)
		add("volume_healthy_steady_app", appInput, ref, volume, volume)
		add("low_intensity", input, ref, mild, mild)
		add("partial_flow_attack", appInput, ref, degraded, missingFlow)
		add("unavailable_app_attack", appInput, ref, missingApp, missingApp)
		add("attack_amid_healthy_growth", appInput, ref, crowdWithOtherPacketMix, crowdWithOtherPacketMix)
		add("matched_flash_crowd", appInput, ref, flash, flash)
		otherPort, sameTotals := flash, flash
		otherPort.OtherBytes, otherPort.OtherPackets = flash.Bytes, flash.Packets
		sameTotals.Bytes, sameTotals.Packets = ref.Bytes, ref.Packets
		sameTotals.OtherBytes, sameTotals.OtherPackets = flash.Bytes-ref.Bytes, flash.Packets-ref.Packets
		add("crowd_with_unrelated_pressure", appInput, ref, otherPort, otherPort)
		add("matched_totals_unrelated_port", appInput, ref, sameTotals, sameTotals)
		add("stable", input, ref, ref, ref)
		add("single_window", input, ref, volume, ref)
		add("below_observation_floor", input, ref, few, few)
		add("inconsistent_pressure", input, ref, syn, volume)
		missingStable := ref
		missingStable.Complete = false
		add("partial_flow_benign", input, ref, missingStable, ref)
		add("app_for_another_host", appInput, ref, foreignApp, foreignApp)
		add("insufficient_app_reference", appInput, weakReference, flash, flash)
		add("flash_crowd_packet_mix", appInput, ref, crowdWithOtherPacketMix, crowdWithOtherPacketMix)
	}
	return trials
}

var benchmarkDDoSServicePorts = map[string]string{"dns": "53", "ntp": "123", "cldap": "389", "ssdp": "1900", "memcached": "11211"}

func benchmarkDDoSRows(window benchmarkDDoSWindow) []flowstore.PlanRow {
	rows := make([]flowstore.PlanRow, 0, window.Addresses)
	for index := range window.Addresses {
		address := netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)})
		group := map[string]string{"dst_addr": address.String(), "dst_port": "443", "sampling": strconv.Itoa(window.Sampling), "transport": "tcp", "tcp_flags": "16"}
		if window.Profile == "syn" {
			group["tcp_flags"] = "2"
		}
		if port := benchmarkDDoSServicePorts[window.Profile]; port != "" {
			group["transport"], group["src_port"] = "udp", port
		}
		rows = append(rows, flowstore.PlanRow{Group: group, Metrics: map[string]string{
			"bytes:total":   strconv.Itoa(benchmarkDDoSShare(window.Bytes, window.Addresses, index)),
			"packets:total": strconv.Itoa(benchmarkDDoSShare(window.Packets, window.Addresses, index)),
			"flows:total":   strconv.Itoa(benchmarkDDoSShare(window.Records, window.Addresses, index)),
		}})
	}
	if window.OtherBytes > 0 || window.OtherPackets > 0 {
		rows = append(rows, flowstore.PlanRow{
			Group:   map[string]string{"dst_addr": "192.0.2.1", "dst_port": "8443", "sampling": "1", "transport": "tcp", "tcp_flags": "16"},
			Metrics: map[string]string{"bytes:total": strconv.Itoa(window.OtherBytes), "packets:total": strconv.Itoa(window.OtherPackets), "flows:total": "24"},
		})
	}
	return rows
}

func benchmarkDDoSShare(total, groups, index int) int {
	portion := total / groups
	if index < total%groups {
		portion++
	}
	return portion
}

func benchmarkDDoSAppSpans(window benchmarkDDoSApplication, from time.Time) []otelstore.Span {
	spans := make([]otelstore.Span, 0, window.Requests)
	host := "192.0.2.1"
	if window.WrongHost {
		host = "192.0.2.2"
	}
	for index := range window.Requests {
		status := "200"
		if index < window.Failures {
			status = "503"
		}
		spans = append(spans, otelstore.Span{TenantID: benchmarkDDoSTenant, TraceID: fmt.Sprintf("%032x", index+1), SpanID: fmt.Sprintf("%016x", index+1),
			Kind: "server", Service: "synthetic-public-site", Start: from.Add(time.Duration(index) * time.Millisecond),
			Duration: time.Duration(window.LatencyMS+index%3) * time.Millisecond,
			Attrs: map[string]string{"http.response.status_code": status, "server.address": "site.example",
				"network.local.address": host, "network.local.port": "443", "network.transport": "tcp"}})
	}
	return spans
}

func benchmarkDDoSCapturedWindow(settings ddosAssessmentSettings, window benchmarkDDoSWindow, from, to time.Time) capturedReportFlow {
	return capturedReportFlow{ID: settings.View.ID, Version: settings.View.Version, TenantID: benchmarkDDoSTenant,
		Result: flowstore.PlanResult{OldestInput: from, Coverage: &flowstore.PlanSourceCoverage{CompleteInputs: window.Complete},
			Query: flow.QueryPlan{View: "table", From: from, To: to}, Source: "raw", ResolutionSeconds: 1, Rows: benchmarkDDoSRows(window)},
	}
}

func benchmarkDDoSProjection(ctx context.Context, settings ddosAssessmentSettings, window benchmarkDDoSWindow, from, to time.Time) (anomaly.DDoSObservation, flow.DDoSWindowEvidence, error) {
	projected, err := projectDDoSWindow(ctx, benchmarkDDoSCapturedWindow(settings, window, from, to), settings, "synthetic-fixture-v2", benchmarkDDoSWork)
	return projected.observation, projected.evidence, err
}

func benchmarkDDoSAssess(ctx context.Context, settings ddosAssessmentSettings, reference, current benchmarkDDoSWindow, clocks anomaly.FlowFieldComparisonClocks) (flow.DDoSAssessment, error) {
	if binding := settings.Input.Application; binding != nil {
		settings.readApplication = func(ctx context.Context, observation anomaly.DDoSObservation) (anomaly.DDoSApplicationWindow, bool, error) {
			window := current.Application
			if observation.From.Equal(clocks.Before.Start) {
				window = reference.Application
			}
			return projectDDoSApplicationWindow(ctx, observation, binding.Service, binding.Port, observation.To, benchmarkDDoSAppSpans(window, observation.From))
		}
	}
	capture := &reportFlowCapture{TenantID: benchmarkDDoSTenant, SourceGeneration: 1, Results: []capturedReportFlow{
		benchmarkDDoSCapturedWindow(settings, reference, clocks.Before.Start, clocks.Before.End),
		benchmarkDDoSCapturedWindow(settings, current, clocks.After.Start, clocks.After.End),
	}}
	return assessCapturedDDoS(ctx, capture, settings, clocks, 0, 1, benchmarkDDoSWork)
}

type benchmarkDDoSOutcome struct {
	Class        anomaly.DDoSClass
	Service      string
	DelaySeconds int
	Residual     bool
	Abstained    bool
	DemandProven bool
}

func benchmarkDDoSEvaluate(ctx context.Context, trial benchmarkDDoSTrial) (benchmarkDDoSOutcome, error) {
	input := trial.Settings
	settings, err := normalizeDDoSAssessment(benchmarkDDoSView, input)
	if err != nil {
		return benchmarkDDoSOutcome{}, err
	}
	end := benchmarkDDoSEpoch.Add(2 * time.Duration(input.PeriodSeconds) * time.Second)
	clocks, err := ddosClocks(end, input.PeriodSeconds)
	if err != nil {
		return benchmarkDDoSOutcome{}, err
	}
	previous, err := benchmarkDDoSAssess(ctx, settings, trial.Reference, trial.Windows[0], clocks.Previous)
	if err != nil {
		return benchmarkDDoSOutcome{Abstained: errors.Is(err, anomaly.ErrDDoSCoverage)}, err
	}
	current, err := benchmarkDDoSAssess(ctx, settings, trial.Reference, trial.Windows[1], clocks.Current)
	if err != nil {
		return benchmarkDDoSOutcome{Abstained: errors.Is(err, anomaly.ErrDDoSCoverage)}, err
	}
	binding := alert.QueryGroupBinding{TenantID: benchmarkDDoSTenant, RuleID: benchmarkDDoSRule, ViewID: settings.View.ID,
		ViewVersion: input.Version, Condition: alert.QueryCondition{Mode: alert.DDoSCondition, DDoS: &input}}
	episode, _, err := alert.EvaluateDDoSEpisode(ctx, binding, alert.QueryGroupState{}, previous, current,
		alert.QueryGroupBudget{MemoryBytes: benchmarkDDoSWork, WorkUnits: benchmarkDDoSWork})
	outcome := benchmarkDDoSOutcome{Abstained: errors.Is(err, anomaly.ErrDDoSCoverage),
		Residual:     current.Application != nil && current.Application.State == anomaly.DDoSApplicationResidual,
		DemandProven: current.Application != nil && current.Application.State == anomaly.DDoSApplicationDemand}
	if err != nil || episode == nil {
		return outcome, err
	}
	onset := benchmarkDDoSEpoch.Add(-time.Duration(trial.OnsetBeforeAligned) * time.Second)
	outcome.Class, outcome.Service = current.Detection.Class, current.Detection.Service
	outcome.DelaySeconds = int(current.After.To.Sub(onset).Seconds())
	return outcome, nil
}

type benchmarkDDoSCounts struct {
	TruePositive, FalsePositive, TrueNegative, FalseNegative int
	AbstainedPositive, AbstainedNegative                     int
}

func (counts *benchmarkDDoSCounts) record(positive bool, outcome benchmarkDDoSOutcome) {
	switch {
	case outcome.Abstained && positive:
		counts.AbstainedPositive++
	case outcome.Abstained:
		counts.AbstainedNegative++
	case outcome.Class != "" && positive:
		counts.TruePositive++
	case outcome.Class != "":
		counts.FalsePositive++
	case positive:
		counts.FalseNegative++
	default:
		counts.TrueNegative++
	}
}

func TestSyntheticDDoSDetectionBenchmark(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	trials, labels := benchmarkDDoSFixture(), benchmarkDDoSLabels()
	if len(trials) != 416 || len(trials) != len(labels)*benchmarkDDoSVars {
		t.Fatalf("v2 corpus has %d trials and %d scenario families", len(trials), len(labels))
	}
	manifest, err := json.Marshal(struct {
		Epoch  time.Time
		Trials []benchmarkDDoSTrial
		Labels map[string]benchmarkDDoSLabel
	}{benchmarkDDoSEpoch, trials, labels})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture_manifest_sha256=%s", hex.EncodeToString(crypto.Hash(manifest)))
	replayCases := make([]syntheticDDoSReplayTrial, 0, len(trials))
	for i, trial := range trials {
		replay, err := materializeSyntheticDDoSReplay(i+1, trial)
		if err != nil {
			t.Fatal(err)
		}
		replayCases = append(replayCases, replay)
	}
	rowsDigest, err := syntheticDDoSRowsDigest(replayCases)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture_rows_sha256=%s", rowsDigest)
	var counts benchmarkDDoSCounts
	delays := []int{}
	truth := make([]syntheticDDoSTruth, 0, len(trials))
	for i, trial := range trials {
		label, ok := labels[trial.Family]
		if !ok {
			t.Fatalf("missing oracle label for %q", trial.Family)
		}
		truth = append(truth, syntheticDDoSTruth{ID: replayCases[i].ID, Scenario: trial.Name, Positive: label.Positive})
		outcome, err := benchmarkDDoSEvaluate(ctx, trial)
		if err != nil && !outcome.Abstained {
			t.Fatalf("assessment %q: %v", trial.Name, err)
		}
		if outcome.Class != label.Class || outcome.Service != label.Service || outcome.Abstained != label.Abstained ||
			outcome.Residual != label.Residual || outcome.DemandProven != label.DemandProven {
			t.Errorf("trial %q produced %+v, oracle expects %+v", trial.Name, outcome, label)
		}
		if outcome.Class != "" {
			if outcome.DelaySeconds != 10+trial.OnsetBeforeAligned {
				t.Errorf("trial %q opened in %ds", trial.Name, outcome.DelaySeconds)
			}
			delays = append(delays, outcome.DelaySeconds)
		}
		counts.record(label.Positive, outcome)
		t.Logf("case=%s label_positive=%t class=%q service=%q abstained=%t demand_explained=%t unrelated_pressure=%t episode_delay_seconds=%d",
			trial.Name, label.Positive, outcome.Class, outcome.Service, outcome.Abstained, outcome.DemandProven, outcome.Residual, outcome.DelaySeconds)
	}
	t.Logf("true_positive=%d false_positive=%d true_negative=%d false_negative=%d abstained_positive=%d abstained_negative=%d",
		counts.TruePositive, counts.FalsePositive, counts.TrueNegative, counts.FalseNegative, counts.AbstainedPositive, counts.AbstainedNegative)
	slices.Sort(delays)
	if len(delays) != 0 {
		t.Logf("onset_min=%d onset_p50=%d onset_p95=%d onset_max=%d", delays[0], delays[(len(delays)-1)/2], delays[(len(delays)*95+99)/100-1], delays[len(delays)-1])
	}
	if dir := os.Getenv("PROBECTL_TEST_DDOS_CORPUS_DIR"); dir != "" && !t.Failed() {
		if err := writeSyntheticDDoSReplay(dir, replayCases, truth, rowsDigest); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkSyntheticDDoSDetection(b *testing.B) {
	ctx := tenancy.WithTenant(b.Context(), tenancy.ID(benchmarkDDoSTenant))
	trials := benchmarkDDoSFixture()
	for b.Loop() {
		for _, trial := range trials {
			outcome, err := benchmarkDDoSEvaluate(ctx, trial)
			if err != nil && !outcome.Abstained {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(len(trials)), "trials/op")
}
