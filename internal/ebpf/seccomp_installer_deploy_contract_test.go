// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"regexp"
	"strings"
	"testing"
)

// TestAgentSeccompInstallerRunsTheVerifiedAgentImage pins RTO-12's busybox
// decision: busybox publishes no cosign signature, so the image-integrity
// policy could never verify the chart's seccomp-installer initContainer. The
// installer now runs the agent image itself (install-seccomp-profile), and
// every container the chart renders uses that one verified image.
func TestAgentSeccompInstallerRunsTheVerifiedAgentImage(t *testing.T) {
	ds := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/daemonset.yaml")
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	schema := readDeployContractFile(t, "deploy/helm/probectl-agent/values.schema.json")
	doc := readDeployContractFile(t, "docs/ebpf-agent.md")

	_, installer, found := strings.Cut(ds, "- name: install-seccomp-profile")
	if !found {
		t.Fatal("daemonset.yaml has no install-seccomp-profile initContainer (EBPF-003)")
	}
	installer, _, _ = strings.Cut(installer, "volumeMounts:")
	for _, want := range []string{
		`image: "{{ .Values.image.repository }}:{{ $imageTag }}"`,
		"- install-seccomp-profile",
		"--src=/profile/seccomp.json",
		"--dest=/host-seccomp/{{ .Values.seccomp.localhostProfile }}",
		"type: RuntimeDefault",
	} {
		if !strings.Contains(installer, want) {
			t.Errorf("seccomp installer initContainer missing %q (RTO-12)", want)
		}
	}
	for _, banned := range []string{"/bin/sh", "installerImage", "busybox"} {
		if strings.Contains(installer, banned) {
			t.Errorf("seccomp installer initContainer still carries %q (RTO-12)", banned)
		}
	}
	if !strings.Contains(ds, `hasKey .Values.seccomp "installerImage"`) {
		t.Error("daemonset.yaml must refuse the removed seccomp.installerImage key (RTO-12)")
	}
	for _, img := range regexp.MustCompile(`(?m)^\s+image: .*$`).FindAllString(ds, -1) {
		if strings.TrimSpace(img) != `image: "{{ .Values.image.repository }}:{{ $imageTag }}"` {
			t.Errorf("DaemonSet renders %q: every container must run the verified agent image (RTO-12)", strings.TrimSpace(img))
		}
	}
	for name, body := range map[string]string{"values.yaml": values, "values.schema.json": schema} {
		if strings.Contains(body, "installerImage") && name == "values.schema.json" {
			t.Errorf("%s still declares seccomp.installerImage (RTO-12)", name)
		}
		if regexp.MustCompile(`(?m)^\s*installerImage:`).MatchString(body) || strings.Contains(body, "busybox:1.36@") {
			t.Errorf("%s still ships the busybox installer image (RTO-12)", name)
		}
	}
	if !strings.Contains(doc, "install-seccomp-profile") || !strings.Contains(doc, "no cosign signature") {
		t.Error("docs/ebpf-agent.md must explain that the installer runs the agent image (RTO-12)")
	}
}
