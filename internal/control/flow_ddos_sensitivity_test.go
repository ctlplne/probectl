// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSyntheticDDoSProtectedServiceSensitivity(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(benchmarkDDoSTenant))
	var trials int
	for _, original := range benchmarkDDoSFixture() {
		if original.Family != "volume_health_drop" {
			continue
		}
		t.Run(original.Name, func(t *testing.T) {
			healthy := original.Reference
			healthy.Bytes = healthy.Bytes * 17 / 10
			healthy.Packets = healthy.Packets * 17 / 10
			healthy.Application.Requests = healthy.Application.Requests * 17 / 10
			degraded := healthy
			degraded.Application.Failures = original.Windows[0].Application.Failures
			degraded.Application.LatencyMS = original.Windows[0].Application.LatencyMS

			// The broad benchmark's floors exceed this service's entire
			// observed window even when the application is degraded.
			trial := original
			trial.Windows = [2]benchmarkDDoSWindow{degraded, degraded}
			outcome, err := benchmarkDDoSEvaluate(ctx, trial)
			if err != nil || outcome.Class != "" || outcome.Abstained {
				t.Fatalf("broad floors should exclude this measured pressure, got %+v, %v", outcome, err)
			}

			// A service operator can configure floors between the original
			// historical population and the smallest held-out surge.
			trial.Settings.BytesFloor, trial.Settings.PacketsFloor = "140000", "1400"
			outcome, err = benchmarkDDoSEvaluate(ctx, trial)
			if !errors.Is(err, anomaly.ErrDDoSCoverage) || outcome.Class != "" || !outcome.Abstained || outcome.DemandProven {
				t.Fatalf("proportionate demand during degraded service must leave pressure ambiguous, got %+v, %v", outcome, err)
			}

			pressure := degraded
			pressure.Application.Requests = trial.Reference.Application.Requests
			trial.Windows = [2]benchmarkDDoSWindow{pressure, pressure}
			outcome, err = benchmarkDDoSEvaluate(ctx, trial)
			if err != nil || outcome.Class != anomaly.DDoSVolumetric || outcome.Abstained ||
				outcome.DelaySeconds != 2*trial.Settings.PeriodSeconds+trial.OnsetBeforeAligned {
				t.Fatalf("lower service floors lost pressure that completed demand could not explain, got %+v, %v", outcome, err)
			}

			trial.Windows = [2]benchmarkDDoSWindow{healthy, healthy}
			outcome, err = benchmarkDDoSEvaluate(ctx, trial)
			if err != nil || outcome.Class != "" || !outcome.DemandProven || outcome.Abstained {
				t.Fatalf("identical healthy flow should be explained by application demand, got %+v, %v", outcome, err)
			}

			unavailable := degraded
			unavailable.Application.Requests = 0
			trial.Windows = [2]benchmarkDDoSWindow{unavailable, unavailable}
			outcome, err = benchmarkDDoSEvaluate(ctx, trial)
			if !errors.Is(err, anomaly.ErrDDoSCoverage) || outcome.Class != "" || !outcome.Abstained {
				t.Fatalf("lower service floors bypassed independent coverage, got %+v, %v", outcome, err)
			}
		})
		trials++
	}
	if trials != benchmarkDDoSVars {
		t.Fatalf("service sensitivity holdout evaluated %d original variations", trials)
	}
	t.Logf("variations=%d broad_floor_misses=%d service_floor_detections=%d healthy_demand_controls=%d degraded_demand_abstentions=%d unavailable_application_controls=%d",
		trials, trials, trials, trials, trials, trials)
}
