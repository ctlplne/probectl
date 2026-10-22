// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"regexp"
	"testing"
)

// The chart publish job never succeeded before DPR-258, and it ran on whatever
// helm the runner image happened to carry. Its digest read was proven against
// helm 3.16.2 and a real registry, which is also the helm the helm-gate renders
// the charts with, so the release job must pin that same version: a runner
// image update must not change how the published chart is packaged and pushed.
func TestChartPublishPinsTheGateHelm(t *testing.T) {
	version := regexp.MustCompile(`azure/setup-helm@[0-9a-f]{40} # v\d+\s+with:\s+version: (v\d+\.\d+\.\d+)`)
	ci := version.FindStringSubmatch(readWorkflow(t, "ci.yml"))
	if ci == nil {
		t.Fatal("ci.yml no longer pins helm with azure/setup-helm and an exact version")
	}
	release := readWorkflow(t, "release.yml")
	publish := version.FindStringSubmatch(jobBlock(t, release, "publish-chart"))
	if publish == nil {
		t.Fatal("release.yml's publish-chart job does not pin helm with azure/setup-helm and an exact version, " +
			"so the chart is packaged and pushed by whatever helm the runner image carries (G1)")
	}
	if publish[1] != ci[1] {
		t.Errorf("release.yml's publish-chart job pins helm %s but the helm-gate renders with %s; "+
			"publish with the helm the charts are tested with (G1)", publish[1], ci[1])
	}
}
