// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package deliveryaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompletenessAuditReplacesProvisionalKafkaDetail(t *testing.T) {
	t.Parallel()

	scriptPath := filepath.Join("..", "..", "scripts", "run_completeness_audit.sh")
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	start := strings.Index(script, "store_probes() {")
	if start < 0 {
		t.Fatal("could not find store_probes in completeness audit script")
	}
	end := strings.Index(script[start:], "\ntool_curl() {")
	if end < 0 {
		t.Fatal("could not isolate store_probes in completeness audit script")
	}
	storeProbes := script[start : start+end]

	if strings.Contains(storeProbes, `.detail +=`) {
		t.Fatal("store_probes appends proven Kafka facts to provisional contradictory detail")
	}
	for _, required := range []string{
		`.detail = "release control was proven connected`,
		`Four product-emitted OTLP records were independently observed`,
		`Kafka reader isolation is not claimed`,
	} {
		if !strings.Contains(storeProbes, required) {
			t.Fatalf("store_probes is missing accurate Kafka detail contract %q", required)
		}
	}
}
