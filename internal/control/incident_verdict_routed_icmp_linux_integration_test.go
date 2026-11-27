// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// A stock FRR hold expiry, real kernel link state and two probes cross the
// same handoff. All retained observations arrive over the issued mTLS lanes.
func TestIncidentVerdictPhysicalCarrierProbeLossKeepsTenantIsolation(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB", "isolated Linux carrier and probe namespaces")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the required carrier probe proof needs namespace privileges")
	}
	proveIncidentCarrier(t, startVerdictCarrierFRR)
}

func collectVerdictCarrierProbes(t *testing.T, vantages [2]string, healthy bool, senders []string, definitions []testspec.ExecutableDefinition) [2]entity.Observation {
	t.Helper()
	var probes [2]entity.Observation
	for i, sample := range collectVerdictICMPPair(t, vantages, definitions) {
		m := sample.Measurement
		wantReplies := 0
		if healthy {
			wantReplies = m.Expected
		}
		if m.TargetIP != definitions[i].Target || m.Expected != 3 || m.Replies != wantReplies ||
			len(m.NetworkErrors) != 0 || sample.Result.Success != healthy {
			t.Fatal("the original probes did not record the planted carrier loss or the healthy control",
				m.TargetIP, m.Expected, m.Replies, len(m.NetworkErrors), sample.Result.Error)
		}
		probes[i] = dependencyPhysicalICMPObservation(t, senders[i], definitions[i], m)
	}
	return probes
}

// Stock FRR, the original selected route and kernel-generated ICMP all come
// from the same isolated path, with separate tenant and mTLS identities.
func TestIncidentVerdictPhysicalExternalNoRouteKeepsTenantIsolation(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB", "isolated Linux carrier, external router and probe namespaces")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the required external routing proof needs namespace privileges")
	}
	proveIncidentInternet(t, startVerdictInternetFRR)
}

func collectVerdictInternetProbes(t *testing.T, vantages [2]string, healthy bool, senders []string, definitions []testspec.ExecutableDefinition) [2]entity.Observation {
	t.Helper()
	var probes [2]entity.Observation
	for i, sample := range collectVerdictICMPPair(t, vantages, definitions) {
		m := sample.Measurement
		wantReplies, wantErrors := 0, m.Expected
		if healthy {
			wantReplies, wantErrors = m.Expected, 0
		}
		if m.TargetIP != definitions[i].Target || m.Expected != 3 || m.Replies != wantReplies ||
			len(m.NetworkErrors) != wantErrors || sample.Result.Success != healthy {
			t.Fatal("the external router did not emit exactly the planted no-route outcomes or the healthy control",
				m.TargetIP, m.Expected, m.Replies, len(m.NetworkErrors), sample.Result.Error)
		}
		for _, original := range m.NetworkErrors {
			if original.Conflicting || original.Type != 3 || original.Code != 0 || original.Responder != verdictFRRExternalIP {
				t.Fatal("incorrect original external network error", original.Type, original.Code, original.Responder)
			}
		}
		probes[i] = dependencyPhysicalICMPObservation(t, senders[i], definitions[i], m)
	}
	return probes
}

func routeVerdictICMPTargets(t *testing.T, network dependencyPhysicalNetwork, origin string, definitions []testspec.ExecutableDefinition) {
	t.Helper()
	for _, definition := range definitions {
		prefix := definition.Target + "/32"
		dependencyLabCommand(t, "ip", "-n", origin, "addr", "add", prefix, "dev", "lo")
		dependencyLabCommand(t, "ip", "-n", network.router, "route", "add", prefix, "via", "10.250.1.2")
		dependencyLabCommand(t, "ip", "-n", network.source, "route", "add", prefix, "via", "10.250.0.1")
	}
}

func checkVerdictICMPBaseline(t *testing.T, vantages [2]string, definitions []testspec.ExecutableDefinition) {
	t.Helper()
	for _, sample := range collectVerdictICMPPair(t, vantages, definitions) {
		if !sample.Result.Success || sample.Measurement.Replies != sample.Measurement.Expected {
			t.Fatal("the routed probe did not reach its healthy baseline", sample.Result.Error)
		}
	}
}

func collectVerdictICMPPair(t *testing.T, vantages [2]string, definitions []testspec.ExecutableDefinition) [2]dependencyPhysicalMeasurement {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var group sync.WaitGroup
	var results [2]dependencyPhysicalMeasurement
	var errors [2]error
	for i, vantage := range vantages {
		output := filepath.Join(t.TempDir(), "measurement.json")
		group.Go(func() {
			results[i], errors[i] = runDependencyPhysicalProbe(ctx, vantage, output, definitions[i])
		})
	}
	group.Wait()
	for i, err := range errors {
		if err != nil {
			t.Fatalf("probe vantage %d failed to retain its originals: %v", i, err)
		}
	}
	return results
}
