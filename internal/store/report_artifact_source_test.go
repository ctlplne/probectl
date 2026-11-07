// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestReportArtifactSourceCaptureVersionsStayTenantBound(t *testing.T) {
	const tenant = "10000000-0000-4000-8000-000000000001"
	for _, version := range []int{1, 2} {
		capture := json.RawMessage(fmt.Sprintf(`{"version":%d,"tenant_id":%q}`, version, tenant))
		if err := reportArtifactSourceCapture(tenant, capture); err != nil {
			t.Fatalf("compatible tenant report receipt version %d refused: %v", version, err)
		}
		if err := reportArtifactSourceCapture("20000000-0000-4000-8000-000000000002", capture); !errors.Is(err, ErrReportArtifactIntegrity) {
			t.Fatalf("version %d source receipt crossed tenant boundary: %v", version, err)
		}
	}
	for _, raw := range []string{`null`, `{}`, `{"version":0}`, `{"version":3}`, `{"version":"2"}`, `[]`, `{`,
		fmt.Sprintf(`{"version":2,"tenant_id":%q} {}`, tenant),
		fmt.Sprintf(`{"version":3,"tenant_id":%q}`, tenant),
		fmt.Sprintf(`{"version":0,"tenant_id":%q}`, tenant)} {
		if err := reportArtifactSourceCapture(tenant, json.RawMessage(raw)); !errors.Is(err, ErrReportArtifactIntegrity) {
			t.Fatalf("invalid report receipt accepted: %s: %v", raw, err)
		}
	}
}
