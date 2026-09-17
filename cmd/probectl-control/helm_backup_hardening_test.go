// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestBackupAndRestorePodsAreHardened (DPR-088): every backup CronJob and
// restore Job container — the chart's and the standalone deploy/backup
// manifests — carries the same container hardening as the control plane (no
// privilege escalation, read-only root filesystem, no capabilities), and every
// pod pins a non-root uid/gid and the runtime seccomp profile. The pods write
// only to their mounted volumes, so nothing needs a writable root filesystem;
// the scheduled trivy misconfiguration scan reported the gap as HIGH
// (KSV-0014). The Postgres restore Job additionally pins the image's postgres
// uid: runAsNonRoot alone can never start a root-default image.
func TestBackupAndRestorePodsAreHardened(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	var docs []string
	for _, tmpl := range []string{"templates/backup-cronjobs.yaml", "templates/restore-job.yaml"} {
		out, err := renderHelmAgentListener(t, tmpl,
			"--set", "backup.enabled=true",
			"--set", "backup.clickhouse.encryptedTargetAck=encrypted-clickhouse-backup-target",
			"--set", "restore.enabled=true",
			"--set-string", "restore.backupFile=postgres-probectl.dump.pbk",
			"--set", "restore.clickhouse.enabled=true",
			"--set-string", "restore.clickhouse.backupFile=clickhouse-probectl.zip.pbk")
		if err != nil {
			t.Fatalf("render %s: %v\n%s", tmpl, err, out)
		}
		docs = append(docs, splitYAMLDocuments(out)...)
	}
	for _, f := range []string{"deploy/backup/k8s-cronjob-postgres.yaml", "deploy/backup/k8s-cronjob-clickhouse.yaml"} {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		docs = append(docs, splitYAMLDocuments(string(raw))...)
	}

	checked := 0
	for _, doc := range docs {
		var obj map[string]any
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			t.Fatalf("parse rendered document: %v\n%s", err, doc)
		}
		var pod map[string]any
		switch obj["kind"] {
		case "CronJob":
			pod = digMap(obj, "spec", "jobTemplate", "spec", "template", "spec")
		case "Job":
			pod = digMap(obj, "spec", "template", "spec")
		default:
			continue
		}
		name, _ := digMap(obj, "metadata")["name"].(string)
		if pod == nil {
			t.Fatalf("%s: no pod spec", name)
		}
		checked++

		psc := digMap(pod, "securityContext")
		if psc["runAsNonRoot"] != true {
			t.Errorf("%s: pod securityContext.runAsNonRoot must be true, got %v", name, psc["runAsNonRoot"])
		}
		for _, key := range []string{"runAsUser", "runAsGroup"} {
			if uid, ok := psc[key].(int); !ok || uid <= 0 {
				t.Errorf("%s: pod securityContext.%s must pin a non-root id, got %v", name, key, psc[key])
			}
		}
		if got := digMap(psc, "seccompProfile")["type"]; got != "RuntimeDefault" {
			t.Errorf("%s: pod seccompProfile.type must be RuntimeDefault, got %v", name, got)
		}
		containers := 0
		for _, list := range []string{"initContainers", "containers"} {
			items, _ := pod[list].([]any)
			for _, item := range items {
				c, _ := item.(map[string]any)
				cname, _ := c["name"].(string)
				containers++
				sc := digMap(c, "securityContext")
				if sc["allowPrivilegeEscalation"] != false {
					t.Errorf("%s/%s: allowPrivilegeEscalation must be false, got %v", name, cname, sc["allowPrivilegeEscalation"])
				}
				if sc["readOnlyRootFilesystem"] != true {
					t.Errorf("%s/%s: readOnlyRootFilesystem must be true, got %v", name, cname, sc["readOnlyRootFilesystem"])
				}
				drop, _ := digMap(sc, "capabilities")["drop"].([]any)
				if len(drop) != 1 || drop[0] != "ALL" {
					t.Errorf("%s/%s: capabilities.drop must be [ALL], got %v", name, cname, drop)
				}
			}
		}
		if containers == 0 {
			t.Errorf("%s: no containers rendered", name)
		}
	}
	// Three chart CronJobs (postgres, clickhouse, object store), two restore
	// Jobs (postgres, clickhouse) and the two standalone CronJob manifests.
	if checked != 7 {
		t.Fatalf("expected 7 backup/restore pod specs, checked %d", checked)
	}
}

// splitYAMLDocuments splits a multi-document YAML stream on `---` lines and
// drops documents that hold nothing but comments or whitespace.
func splitYAMLDocuments(stream string) []string {
	var docs []string
	for _, part := range strings.Split("\n"+stream, "\n---") {
		meaningful := false
		for _, line := range strings.Split(part, "\n") {
			if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "#") {
				meaningful = true
				break
			}
		}
		if meaningful {
			docs = append(docs, part)
		}
	}
	return docs
}

// digMap walks nested map[string]any keys and returns an empty map (never
// nil) when the path does not exist, so callers can index freely.
func digMap(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return map[string]any{}
		}
		cur = next
	}
	if cur == nil {
		return map[string]any{}
	}
	return cur
}
