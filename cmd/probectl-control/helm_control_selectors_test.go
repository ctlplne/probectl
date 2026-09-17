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
	for _, tpl := range []string{"templates/pdb.yaml", "templates/networkpolicy.yaml"} {
		out, err := renderHelmAgentListener(t, tpl,
			"--set", "podDisruptionBudget.enabled=true",
			"--set", "networkPolicy.enabled=true",
			"--set-json", `networkPolicy.ingressFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress-nginx"}}}]`)
		if err != nil {
			t.Fatalf("render %s: %v\n%s", tpl, err, out)
		}
		if !strings.Contains(out, component) {
			t.Errorf("%s must select the control component only:\n%s", tpl, out)
		}
	}
	// The Services deliberately keep the release-wide selector: a selector
	// narrowed to a label the running pods lack is applied before any new pod
	// exists and orphans every old replica for the length of the rollout (the
	// lab measured 14 s / 27 failed requests). The named targetPort already
	// excludes the agent pods.
	svc, err := renderHelmAgentListener(t, "templates/service.yaml", "--set", "control.agentListener.enabled=true")
	if err != nil {
		t.Fatalf("render service: %v\n%s", err, svc)
	}
	if strings.Contains(svc, component) {
		t.Errorf("a Service selector must never require a label that running pods lack (zero-downtime upgrade):\n%s", svc)
	}
	if strings.Count(svc, "targetPort: ") < 2 || !strings.Contains(svc, "targetPort: agent-grpc") {
		t.Errorf("the Services must target NAMED ports so agent pods stay out of the endpoints:\n%s", svc)
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
