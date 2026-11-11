// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMainCIQueueKeepsRunningWorkAndNarrowAuthority(t *testing.T) {
	var workflow struct {
		Permissions map[string]string `yaml:"permissions"`
		Concurrency struct {
			Group            string `yaml:"group"`
			CancelInProgress bool   `yaml:"cancel-in-progress"`
			Queue            string `yaml:"queue"`
		} `yaml:"concurrency"`
	}
	if err := yaml.Unmarshal([]byte(readWorkflow(t, "ci.yml")), &workflow); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(workflow.Permissions, map[string]string{"contents": "read"}) || workflow.Concurrency.CancelInProgress || workflow.Concurrency.Queue != "single" {
		t.Fatal("full CI must retain read-only default authority and preserve running work")
	}
	for _, required := range []string{"github.event_name == 'push' && github.ref == 'refs/heads/main'", "'619e37b0b601671b90840237c34c9d8ecb88087d'", "github.event_name == 'pull_request' && github.ref", "format('protected-{0}', github.run_id)"} {
		if !strings.Contains(workflow.Concurrency.Group, required) {
			t.Fatal("main queue lost stable lane or protected-run separation", required)
		}
	}
	for _, removed := range []string{".github/workflows/ci-development.yml", "scripts/ci_development.py"} {
		if _, err := os.Stat(filepath.Join(repoRoot(t), removed)); !os.IsNotExist(err) {
			t.Fatal("running-CI cancellation controller must remain absent", removed, err)
		}
	}
}
