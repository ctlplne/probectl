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

// TestWORMSegmentsHaveTheirOwnVolume (DPR-116): the chart used to read the WORM
// directory out of control.extraEnv and then demand objectStore.enabled=true,
// objectStore.mode=filesystem and an objectStore claim — so an operator who
// pointed tenant artifacts at S3/MinIO, which is the normal thing to do, could
// not have signed write-once audit segments at all. The chart refused to
// render: "PROBECTL_AUDIT_WORM_DIR requires objectStore.mode=filesystem".
// WORM is a separate durability requirement and now has a separate volume.
func TestWORMSegmentsHaveTheirOwnVolume(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	s3 := []string{
		"--set", "objectStore.enabled=true",
		"--set", "objectStore.mode=s3",
		"--set", "objectStore.s3.endpoint=https://minio.example:9000",
		"--set", "objectStore.s3.bucket=artifacts",
		"--set", "objectStore.s3.accessKey=key",
		"--set", "secrets.objectStoreS3SecretKey=secret",
	}
	worm := []string{"--set", "audit.worm.enabled=true", "--set", "audit.worm.existingClaim=probectl-worm"}

	dep, err := renderHelmAgentListener(t, "templates/deployment.yaml", append(append([]string{}, s3...), worm...)...)
	if err != nil {
		t.Fatalf("an S3 artifact store with WORM audit segments must render: %v\n%s", err, dep)
	}
	for _, want := range []string{
		`- name: audit-worm`,
		`mountPath: "/var/lib/probectl/audit-worm"`,
		`claimName: "probectl-worm"`,
	} {
		if !strings.Contains(dep, want) {
			t.Errorf("the WORM claim must be mounted on its own: missing %q", want)
		}
	}
	if strings.Contains(dep, "name: tenant-objects") {
		t.Error("an s3 artifact store must not also mount a filesystem artifact volume")
	}

	cm, err := renderHelmAgentListener(t, "templates/configmap.yaml", append(append([]string{}, s3...), worm...)...)
	if err != nil {
		t.Fatalf("render configmap: %v\n%s", err, cm)
	}
	if !strings.Contains(cm, `PROBECTL_AUDIT_WORM_DIR: "/var/lib/probectl/audit-worm"`) {
		t.Error("the chart must name the WORM directory from its typed value")
	}

	// Durability is still fail-closed: WORM without a claim is refused, because
	// an emptyDir is not write-once storage.
	if out, err := renderHelmAgentListener(t, "templates/configmap.yaml", "--set", "audit.worm.enabled=true"); err == nil {
		t.Error("audit.worm.enabled without a claim must be refused")
	} else if !strings.Contains(out, "audit.worm.existingClaim") {
		t.Errorf("the refusal must name the missing value, got: %s", out)
	}

	// And the old hand-set environment variable is refused with the migration.
	if out, err := renderHelmAgentListener(t, "templates/configmap.yaml",
		"--set", `control.extraEnv.PROBECTL_AUDIT_WORM_DIR=/var/lib/probectl/objects`); err == nil {
		t.Error("setting the WORM directory through extraEnv must be refused")
	} else if !strings.Contains(out, "audit.worm.enabled") {
		t.Errorf("the refusal must point at the typed value, got: %s", out)
	}
}
