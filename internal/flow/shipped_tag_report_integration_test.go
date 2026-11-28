// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestShippedTaggedFlowReportKeepsCurrentOwnedScope(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "tagreport", TenantBand: 3})
	operator := st.OnboardOperator(t, "root@msp-tag-report.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	const tagField = "tag.customer"
	type reportLane struct {
		nativeLane
		value, tagID, assignmentPath string
		assignment                   map[string]string
		view                         flow.SavedQueryView
		dashboard                    mcp.ReportDashboard
	}
	// Use identical exporter and traffic addresses, tag keys, and context labels.
	// Distinct values and wire counter totals expose any cross-tenant join.
	lanes := []reportLane{
		{nativeLane: nativeLane{name: "red", octet: 181, bytes: 1000}, value: "red-original"},
		{nativeLane: nativeLane{name: "blue", octet: 181, bytes: 5000}, value: "blue-owned"},
	}
	for i := range lanes {
		lanes[i].provision(t, st, operator, run)
	}
	at := time.Now().UTC()
	for i := range lanes {
		lanes[i].send(t)
	}
	for i := range lanes {
		lane := &lanes[i]
		lane.awaitFlows(t, st, at)
		plan := nativeGoldenPlan(lane.octet, at, []string{"exporter"})
		plan.Filter.Conditions = append(plan.Filter.Conditions,
			flow.QueryPredicate{Field: "protocol", Op: flow.QueryEqual, Values: []string{"netflow5"}})
		plan.Metrics = plan.Metrics[:1]
		result := lane.query(t, st, plan)
		if len(result.Rows) != 1 || result.Rows[0].Group["exporter"] != "127.0.0.1" ||
			result.Totals["bytes:total"] != strconv.FormatUint(uint64(lane.bytes), 10) {
			t.Fatalf("%s did not receive its one NetFlow record from the shared exporter address", lane.name)
		}
		var routingContext entity.ContextRecord
		lane.do(t, st, http.MethodPost, "/v1/entity-contexts", map[string]string{"site_label": "Customer site", "vrf_label": "Customer VRF"}, &routingContext, http.StatusCreated)
		lane.do(t, st, http.MethodPut, "/v1/entity-source-contexts", map[string]string{
			"agent_id": lane.agent, "source_kind": "flow_exporter", "source_ref": "127.0.0.1", "context_id": routingContext.ContextID,
		}, nil, http.StatusOK)
		var definition tags.Definition
		lane.do(t, st, http.MethodPost, "/v1/tags", map[string]string{"key": "customer"}, &definition, http.StatusCreated)
		lane.tagID = definition.ID
		lane.assignment = map[string]string{
			"tag_id": lane.tagID, "target_kind": "exporter", "exporter_agent_id": lane.agent,
			"exporter_source_ref": "127.0.0.1", "value": lane.value,
		}
		path := "/v1/entity-contexts/" + routingContext.ContextID + "/tag-assignments"
		var assignment struct{ ID string }
		lane.do(t, st, http.MethodPost, path, lane.assignment, &assignment, http.StatusCreated)
		if lane.tagID == "" || assignment.ID == "" {
			t.Fatalf("%s tag definition or assignment has no identity", lane.name)
		}
		lane.assignmentPath = path + "/" + assignment.ID
		plan.GroupBy = []string{tagField}
		lane.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{
			Name: "Tagged historical data", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan,
		}}, &lane.view, http.StatusCreated)
		if lane.view.Definition.TagIDs[tagField] != lane.tagID {
			t.Fatalf("%s saved view did not bind its own tag definition", lane.name)
		}
		lane.do(t, st, http.MethodPost, "/v1/dashboards", reporting.DashboardCreateInput{
			Name: "Tagged historical report", Preset: "operator",
			Definition: reporting.DashboardDefinition{
				FlowSources:         []reporting.FlowSourceRef{{ID: lane.view.ID, Version: lane.view.Version}},
				Provenance:          []string{"Generated NetFlow packets received by the shipped collector"},
				RedactionState:      "tenant-scoped",
				CoverageLimitations: []string{"Loopback traffic from a protocol fixture"},
			},
		}, &lane.dashboard, http.StatusCreated)
	}

	generate := func(lane, sibling *reportLane) int64 {
		t.Helper()
		var artifact mcp.ReportArtifact
		lane.do(t, st, http.MethodPost, "/v1/dashboard-reports", reporting.ReportGenerateInput{
			DashboardID: lane.dashboard.ID, Format: "csv",
		}, &artifact, http.StatusCreated)
		path := "/v1/dashboard-report-artifacts/" + artifact.ID
		sibling.do(t, st, http.MethodGet, path, nil, nil, http.StatusNotFound)
		status, body := st.Do(t, lane.cookie, http.MethodGet, path, nil)
		if status != http.StatusOK {
			t.Fatalf("%s could not download its report: status %d", lane.name, status)
		}
		tableID := lane.view.ID + "/" + lane.view.Version + "/current/detail"
		return verifyTaggedFlowReportCSV(t, body, lane.id, tableID, tagField, lane.tagID, lane.value, strconv.FormatUint(uint64(lane.bytes), 10))
	}
	owner, sibling := &lanes[0], &lanes[1]
	ownerRevision, siblingRevision := generate(owner, sibling), generate(sibling, owner)
	owner.value = "red-current"
	owner.assignment["value"] = owner.value
	owner.do(t, st, http.MethodPut, owner.assignmentPath, owner.assignment, nil, http.StatusOK)
	// Generate again from the same saved view and earlier wire inputs.
	if next := generate(owner, sibling); next <= ownerRevision {
		t.Fatalf("updated owner report captured tag revision %d after %d", next, ownerRevision)
	}
	if next := generate(sibling, owner); next != siblingRevision {
		t.Fatalf("owner retag advanced the sibling report's tag revision from %d to %d", siblingRevision, next)
	}
}

func verifyTaggedFlowReportCSV(t *testing.T, body []byte, tenant, tableID, field, tagID, value, counter string) int64 {
	t.Helper()
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read tagged report CSV: %v", err)
	}
	metadata := make(map[string]string)
	detail := false
	groupCol, metricCol, records := -1, -1, 0
	for _, row := range rows {
		if len(row) == 2 && row[0] == "table_id" {
			detail = row[1] == tableID
		}
		if !detail {
			continue
		}
		switch row[0] {
		case "record_type":
			groupCol, metricCol = slices.Index(row, field), slices.Index(row, "bytes:total")
		case "detail":
			if groupCol < 0 || metricCol < 0 || groupCol >= len(row) || metricCol >= len(row) || row[groupCol] != value || row[metricCol] != counter {
				t.Fatalf("report did not contain the owned tag %q and wire byte total %s", value, counter)
			}
			records++
		default:
			if len(row) == 2 {
				metadata[row[0]] = row[1]
			}
		}
	}
	revision, err := strconv.ParseInt(metadata["table_tag_revision"], 10, 64)
	if records != 1 || metadata["table_tenant_scope"] != tenant || metadata["table_field_id:"+field] != tagID || err != nil || revision < 1 {
		t.Fatalf("report detail has %d rows and fails the owned tag identity or revision check", records)
	}
	return revision
}
