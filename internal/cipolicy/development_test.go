// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDevelopmentCoalescerKeepsTrustedCodeAndNarrowAuthority(t *testing.T) {
	var workflow struct {
		On map[string]struct {
			Workflows []string `yaml:"workflows"`
			Types     []string `yaml:"types"`
		} `yaml:"on"`
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			If          string            `yaml:"if"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(readWorkflow(t, "ci-development.yml")), &workflow); err != nil {
		t.Fatal(err)
	}
	trigger, ok := workflow.On["workflow_run"]
	if !ok || len(workflow.On) != 1 || !reflect.DeepEqual(trigger.Workflows, []string{"ci"}) || !reflect.DeepEqual(trigger.Types, []string{"in_progress"}) {
		t.Fatal("coalescer must receive only CI workflow start notifications")
	}
	if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read"}) || len(workflow.Jobs) != 1 {
		t.Fatal("coalescer requires read-only default authority and one classified job")
	}
	job, ok := workflow.Jobs["coalesce"]
	wantIf := "github.event.workflow_run.event == 'push' && github.event.workflow_run.head_branch == 'main' && github.event.workflow_run.head_repository.full_name == github.repository && github.event.workflow_run.run_attempt == 1"
	if !ok || job.If != wantIf || !reflect.DeepEqual(job.Permissions, map[string]string{"contents": "read", "actions": "write"}) || len(job.Steps) != 3 {
		t.Fatal("write-capable coalescing must be limited to owned, first-attempt main pushes")
	}
	checkout, execute, upload := job.Steps[0], job.Steps[1], job.Steps[2]
	if checkout.Uses != "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10" || !reflect.DeepEqual(checkout.With, map[string]string{"ref": "${{ github.sha }}", "persist-credentials": "false"}) {
		t.Fatal("coalescer must checkout trusted default-branch SHA, without credentials or upstream code")
	}
	if execute.Run != "python3 scripts/ci_development.py" || !reflect.DeepEqual(execute.Env, map[string]string{"GH_TOKEN": "${{ github.token }}", "SOURCE_RUN_ID": "${{ github.event.workflow_run.id }}"}) {
		t.Fatal("coalescer may execute only its trusted metadata helper")
	}
	if upload.Uses != "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" || upload.With["path"] != "artifacts/ci-development/" || upload.With["retention-days"] != "90" {
		t.Fatal("cancellation receipts must be retained")
	}
}
