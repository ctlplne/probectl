// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportCanonicalSourcesRequireCompleteContextLineageAndCurrentPermissions(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	capture := reportRequirementsFixture(tenant)
	capture.ContextSources = true
	capture.Permissions = []string{permAIQuery, permFlowRead, "entities.read", "metrics.read", "events.read"}
	capture.Contexts[0].Permissions = []string{permFlowRead, "entities.read", "metrics.read", "events.read"}
	capture.Inputs[0].TagRevision, capture.Inputs[0].TagAsOf = "", time.Time{}
	raw, err := marshalReportSourceRequirements(ctx, capture)
	if err != nil || !bytes.Contains(raw, []byte(`"version":2`)) || !bytes.Contains(raw, []byte(`"context_sources":true`)) {
		t.Fatal("role-only report cannot retain its complete current context lineage", err)
	}
	parsed, err := parseReportSourceRequirements(ctx, raw)
	if err != nil || !parsed.ContextSources || !parsed.ContextsCaptured || len(parsed.Contexts) != 1 || len(parsed.Contexts[0].Permissions) != 4 {
		t.Fatal("stored canonical report discarded current source-plane requirements", err)
	}
	capture.ContextSources = false
	if _, err := marshalReportSourceRequirements(ctx, capture); err == nil {
		t.Fatal("canonical report omitted its required context-capture lineage")
	}
	capture.ContextSources, capture.ContextsCaptured = true, false
	if _, err := marshalReportSourceRequirements(ctx, capture); err == nil {
		t.Fatal("canonical report treated an unexecuted context capture as authority")
	}
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["version"] = json.RawMessage(`1`)
	delete(legacy, "context_sources")
	old, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := parseReportSourceRequirements(ctx, old); err == nil || value != nil {
		t.Fatal("legacy canonical report invented complete context lineage")
	}
}
