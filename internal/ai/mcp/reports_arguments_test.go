// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
)

func reportMapProbe[A any](raw string) (A, error) {
	var received A
	tool := reportTool("report-map-probe", "typed argument fixture", json.RawMessage(`{"type":"object"}`), true,
		func(_ context.Context, _ *auth.Principal, input A) (A, error) {
			received = input
			return input, nil
		})
	_, err := tool.Invoke(context.Background(), nil, json.RawMessage(raw))
	return received, err
}

func TestReportArgumentsKeepExactTypedMaps(t *testing.T) {
	const binding = `{"source_bindings":{"flow-1":{"id":"d8eb101f-f425-4427-a706-6c2eeef7bb07","version":"9007199254740993"}},"confirm":false}`
	input, err := reportMapProbe[reporting.DashboardManifestImportInput](binding)
	if err != nil || len(input.SourceBindings) != 1 || input.SourceBindings["flow-1"].ID != "d8eb101f-f425-4427-a706-6c2eeef7bb07" || input.SourceBindings["flow-1"].Version != "9007199254740993" || input.Confirm {
		t.Fatal("native report rejected or changed its declared source binding", err)
	}
	const metrics = `{"definition":{"metrics":{"Exact value":"9007199254740993"}}}`
	dashboard, err := reportMapProbe[reporting.DashboardCreateInput](metrics)
	if err != nil || len(dashboard.Definition.Metrics) != 1 || dashboard.Definition.Metrics["Exact value"] != "9007199254740993" {
		t.Fatal("native report rejected or changed its declared metric map", err)
	}
	if err := decodeBoundedNativeArgs(json.RawMessage(binding), new(reporting.DashboardManifestImportInput), 64<<10); err == nil {
		t.Fatal("ordinary native arguments acquired report map admission")
	}
	if err := decodeBoundedNativeArgs(json.RawMessage(metrics), new(reporting.DashboardCreateInput), 64<<10); err == nil {
		t.Fatal("ordinary native arguments acquired report metric admission")
	}
}

func TestReportArgumentsRefuseUndeclaredMapShapes(t *testing.T) {
	for _, raw := range []string{
		`{"source_bindings":{"flow-1":{"id":"same","version":"1","tenant_id":"foreign"}}}`,
		`{"source_bindings":{"flow-1":{"ID":"same","version":"1"}}}`,
		`{"source_bindings":{"flow-1":{"id":"same","id":"other","version":"1"}}}`,
		`{"source_bindings":{"flow-1":{"id":"same","version":1}}}`,
		`{"source_bindings":{"flow-1":{"id":"same","version":"1"},"FLOW-1":{"id":"other","version":"1"}}}`,
		`{"source_bindings":[]}`,
		`{"source_bindings":{"flow-1":"same"}}`,
		`{"source_bindings":{"flow-1":{"id":"same","version":"1"}},"tenant_id":"foreign"}`,
		`{"Source_bindings":{}}`,
		`{"source_bindings":{}} {}`,
		`{"source_bindings":{"flow-1":{"id":"` + strings.Repeat("x", 64<<10) + `","version":"1"}}}`,
	} {
		if _, err := reportMapProbe[reporting.DashboardManifestImportInput](raw); err == nil {
			t.Fatal("native report accepted an undeclared binding shape")
		}
	}
	for _, raw := range []string{
		`{"definition":{"metrics":{"Exact":{"value":"1"}}}}`,
		`{"definition":{"metrics":{"Exact":1}}}`,
		`{"definition":{"metrics":{"Exact":"1","EXACT":"2"}}}`,
		`{"definition":{"metrics":[]}}`,
	} {
		if _, err := reportMapProbe[reporting.DashboardCreateInput](raw); err == nil {
			t.Fatal("native report accepted an undeclared metric shape")
		}
	}
	if _, err := reportMapProbe[struct {
		Values map[string]any `json:"values"`
	}](`{"values":{"authority":"foreign"}}`); err == nil {
		t.Fatal("report adapter admitted an arbitrary map")
	}
}
