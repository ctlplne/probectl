// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// DPR-085: the browser-agent DaemonSet and the BGP-analyzer Job carry the
// chart's name/instance labels, so every control-owned selector that stopped
// there also selected those pods — the PodDisruptionBudget counted agent pods
// as control replicas (expectedPods 5 for 3 replicas on the lab) and the
// control NetworkPolicy's egress allow-all was unioned onto the browser
// agent's tight policy. The Service, the budget and the policy now select on
// the control component; the Deployment's immutable selector is unchanged and
// its pod template carries the component.
func TestHelmControlSelectorsExcludeAgentPods(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	const component = "app.kubernetes.io/component: control"
	for _, tpl := range []string{"templates/service.yaml", "templates/pdb.yaml", "templates/networkpolicy.yaml"} {
		out, err := renderHelmAgentListener(t, tpl,
			"--set", "control.agentListener.enabled=true",
			"--set", "podDisruptionBudget.enabled=true",
			"--set", "networkPolicy.enabled=true",
			"--set-json", `networkPolicy.ingressFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress-nginx"}}}]`)
		if err != nil {
			t.Fatalf("render %s: %v\n%s", tpl, err, out)
		}
		if !strings.Contains(out, component) {
			t.Errorf("%s must select the control component only:\n%s", tpl, out)
		}
		if tpl == "templates/service.yaml" && strings.Count(out, component) < 2 {
			t.Errorf("both the API and the agent-listener Service must select the control component:\n%s", out)
		}
	}
	out, err := renderHelmAgentListener(t, "templates/deployment.yaml")
	if err != nil {
		t.Fatalf("render deployment: %v\n%s", err, out)
	}
	if !strings.Contains(out, component) {
		t.Errorf("the control pod template must carry the component label:\n%s", out)
	}
	sel := out[strings.Index(out, "  selector:"):]
	sel = sel[:strings.Index(sel, "  template:")]
	if strings.Contains(sel, "component") {
		t.Errorf("the Deployment selector is immutable and must stay name/instance for in-place upgrades:\n%s", sel)
	}
}
