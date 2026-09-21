// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestHelmSLODefinitionsReachTheControlPlane (DPR-064): the SLO engine reads
// OpenSLO files from PROBECTL_SLO_DIR, but the control Deployment had no way
// to carry an operator file, so setting the variable crash-looped the control
// plane (fail closed on a missing directory). A typed ConfigMap mount now
// provisions the definitions and sets the variable; the variable is chart-owned.
func TestHelmSLODefinitionsReachTheControlPlane(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	out, err := renderHelmAgentListener(t, "templates/deployment.yaml", "--set", "control.slo.existingConfigMap=slo-defs")
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	for _, want := range []string{
		"name: PROBECTL_SLO_DIR",
		`value: "/etc/probectl/slo"`,
		"name: slo-definitions",
		`mountPath: "/etc/probectl/slo"`,
		`name: "slo-defs"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered Deployment lacks %q", want)
		}
	}
	// --reuse-values from a release that predates control.slo: the ConfigMap is
	// named but no mountPath exists — the template must default it, or the
	// apply fails with "volumeMounts[n].mountPath: Required value".
	reused, err := renderHelmAgentListener(t, "templates/deployment.yaml", "--set-json", `control.slo={"existingConfigMap":"slo-defs"}`)
	if err != nil {
		t.Fatalf("render: %v\n%s", err, reused)
	}
	if !strings.Contains(reused, `mountPath: "/etc/probectl/slo"`) || !strings.Contains(reused, `value: "/etc/probectl/slo"`) {
		t.Errorf("missing mountPath must default to /etc/probectl/slo:\n%s", reused)
	}
	plain, err := renderHelmAgentListener(t, "templates/deployment.yaml")
	if err != nil {
		t.Fatalf("render: %v\n%s", err, plain)
	}
	if strings.Contains(plain, "PROBECTL_SLO_DIR") {
		t.Error("no ConfigMap named, yet PROBECTL_SLO_DIR rendered")
	}
	extra, err := renderHelmAgentListener(t, "templates/deployment.yaml",
		"--set-json", `control.extraVolumes=[{"name":"ops","configMap":{"name":"ops-files"}}]`,
		"--set-json", `control.extraVolumeMounts=[{"name":"ops","mountPath":"/etc/probectl/ops","readOnly":true}]`)
	if err != nil {
		t.Fatalf("render: %v\n%s", err, extra)
	}
	if !strings.Contains(extra, "mountPath: /etc/probectl/ops") || !strings.Contains(extra, "name: ops-files") {
		t.Errorf("operator volumes not rendered for the control container:\n%s", extra)
	}
	if out, err := renderHelmAgentListener(t, "templates/configmap.yaml", "--set-string", "control.extraEnv.PROBECTL_SLO_DIR=/tmp"); err == nil {
		t.Fatalf("chart-owned PROBECTL_SLO_DIR accepted through extraEnv:\n%s", out)
	}
}
