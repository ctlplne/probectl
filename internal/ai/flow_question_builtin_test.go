// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func questionClock() time.Time { return time.Date(2026, 10, 29, 9, 30, 0, 123456789, time.UTC) }

func planFlowQuestion(t *testing.T, question string, parent *FlowQuestionProposal) FlowQuestionProposal {
	t.Helper()
	planner, err := NewBuiltinFlowQuestionPlanner(DefaultFlowQuestionBudget())
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := planner.Plan(t.Context(), FlowQuestionInput{Question: question, Parent: parent, Now: questionClock(), TimeZone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

func TestBuiltinFlowQuestionComposesNativeReachAndAllMetricCalculations(t *testing.T) {
	for _, definition := range flow.QueryMetricDefinitions() {
		for _, calculation := range definition.Calculations {
			question := fmt.Sprintf("show %s %s by source IP over the last 401 days all rows page size 5000", calculation, definition.Name)
			proposal := planFlowQuestion(t, question, nil)
			if proposal.Status != FlowQuestionReady || proposal.Plan.RowLimit != 2147483647 || proposal.Plan.PageSize != 5000 || len(proposal.Plan.Metrics) != 1 || proposal.Plan.Metrics[0].Measure != definition.Name || proposal.Plan.Metrics[0].Calculation != calculation || proposal.Plan.To.Sub(proposal.Plan.From) != 401*24*time.Hour || proposal.Plan.To.Nanosecond() != 123456789 {
				t.Fatal("metric/time/detail reach lost", question, proposal.Status)
			}
		}
	}
	for _, field := range flow.QueryFields() {
		proposal := planFlowQuestion(t, "show bps by "+field.Name, nil)
		if proposal.Status != FlowQuestionReady || !reflect.DeepEqual(proposal.Plan.GroupBy, []string{field.Name}) {
			t.Fatal("field grouping unreachable", field.Name, proposal.Status)
		}
	}
}

func TestBuiltinFlowQuestionFullMatrixAndSecondaryRoles(t *testing.T) {
	fields := flow.QueryFields()
	var rows, columns []string
	for _, field := range fields[:8] {
		rows = append(rows, field.Name)
	}
	for _, field := range fields[8:16] {
		columns = append(columns, field.Name)
	}
	question := "show avg bps and p95 pps and p99 fps and max bytes and total packets by " + strings.Join(rows, ",") + " matrix with " + strings.Join(columns, ",") + " limit 350 page size 350 every 1 week using rollups series 40 matrix depth 15 ipv4 prefix /0 ipv6 prefix /64"
	proposal := planFlowQuestion(t, question, nil)
	if proposal.Status != FlowQuestionReady || proposal.Plan.View != "matrix" || len(proposal.Plan.GroupBy) != 8 || len(proposal.Plan.MatrixWith) != 8 || proposal.Plan.BucketSeconds != 604800 || proposal.Plan.DataSeries != "rollup" || *proposal.Plan.IPv4PrefixLength != 0 || *proposal.Plan.IPv6PrefixLength != 64 {
		t.Fatal("full matrix/control reach lost", proposal.Status)
	}
	for index, metric := range proposal.Plan.Metrics {
		want := "secondary"
		if index == 0 {
			want = "primary"
		}
		if index > 3 {
			want = "additional"
		}
		if metric.Role != want {
			t.Fatal("metric chart/table roles changed", index, metric.Role)
		}
	}
}

func TestBuiltinFlowQuestionFullMetricAndConditionReachInOneQuestion(t *testing.T) {
	var metrics []string
	for _, definition := range flow.QueryMetricDefinitions() {
		for _, calculation := range definition.Calculations {
			metrics = append(metrics, calculation+" "+definition.Name)
		}
	}
	conditions := make([]string, flow.MaxQueryPredicates)
	for index := range conditions {
		conditions[index] = fmt.Sprintf("source port equals %d", index)
	}
	question := "show " + strings.Join(metrics, ", ") + " where " + strings.Join(conditions, " or ") + " and group by source IP and every 1 minute and over last 401 days all rows page size 5000"
	proposal := planFlowQuestion(t, question, nil)
	if proposal.Status != FlowQuestionReady || len(proposal.Plan.Metrics) != len(metrics) || proposal.Plan.RowLimit != 2147483647 || proposal.Plan.BucketSeconds != 60 || proposal.Plan.To.Sub(proposal.Plan.From) != 401*24*time.Hour {
		t.Fatal("one compositional question lost full native reach", proposal.Status)
	}
	var count func(flow.QueryFilterGroup) int
	count = func(group flow.QueryFilterGroup) int {
		total := len(group.Conditions)
		for _, child := range group.Groups {
			total += count(child)
		}
		return total
	}
	if count(*proposal.Plan.Filter) != flow.MaxQueryPredicates {
		t.Fatal("conditions truncated during clause boundary handling")
	}
	over := planFlowQuestion(t, question+" where source port equals 65535", nil)
	if over.Status != FlowQuestionClarify || over.Plan != nil {
		t.Fatal("multiple filter clauses bypassed aggregate condition guard")
	}
}

func TestBuiltinFlowQuestionFilterTailPreservesPredicateAndGroupMeaning(t *testing.T) {
	for _, question := range []string{
		`show bps where source port equals 443 and source IP in subnet 192.0.2.0/24 and group by destination IP`,
		`show bps where all of(source port equals 443, destination port equals 8443) and every 5 minutes and as line`,
	} {
		proposal := planFlowQuestion(t, question, nil)
		if proposal.Status != FlowQuestionReady || proposal.Plan.Filter == nil || len(proposal.Plan.Filter.Conditions) != 2 {
			t.Fatal("predicate or query tail was swallowed", question, proposal.Status)
		}
	}
	for _, question := range []string{
		`show bps where all of(source port equals 443 and every 5 minutes)`,
		`show bps where source port equals 443 and unknown clause`,
		`show bps where source port equals 443 and source IP`,
		`show bps where source port equals 443 or as line`,
	} {
		proposal := planFlowQuestion(t, question, nil)
		if proposal.Status != FlowQuestionClarify || proposal.Plan != nil {
			t.Fatal("incomplete predicate became a partial read", question)
		}
	}
}

func TestBuiltinFlowQuestionAllDisplayControlsUseSelectedMetricKeys(t *testing.T) {
	proposal := planFlowQuestion(t, `show avg bps and p95 pps as percent area log scale for avg bps and p95 pps percent basis visible independent axes one chart with all series chart height short charts per row 3`, nil)
	if proposal.Status != FlowQuestionReady || proposal.Display == nil || proposal.Display.TimeStyle != "percent_area" || proposal.Display.PercentBasis != "visible" || !reflect.DeepEqual(proposal.Display.LogMetrics, []string{"bps:avg", "pps:p95"}) || proposal.Display.SyncAxes || proposal.Display.OneChartPerSeries || proposal.Display.ChartHeight != "short" || proposal.Display.ChartsPerRow != 3 {
		t.Fatal("display controls lost native values", proposal.Status)
	}
	linear := planFlowQuestion(t, "linear scale", &proposal)
	if linear.Status != FlowQuestionReady || len(linear.Display.LogMetrics) != 0 {
		t.Fatal("explicit linear scale retained inherited logarithms")
	}
	unknown := planFlowQuestion(t, "log scale for total bytes", &proposal)
	if unknown.Status != FlowQuestionClarify || unknown.Plan != nil {
		t.Fatal("unselected metric entered display")
	}
}

func TestBuiltinFlowQuestionCombinesFiltersAndDisplayWithExactValues(t *testing.T) {
	question := `show total bytes by source IP as horizon horizon scale per lane charts per row 4 chart height tall total overlay synchronize axes one chart per series every 1.5 minutes where all of(raw_bytes gt 18446744073709551615, any of(source port in port range 443-445, destination port equals 8443), exclude(dst_country equals "US"))`
	proposal := planFlowQuestion(t, question, nil)
	if proposal.Status != FlowQuestionReady || proposal.Plan.View != "line" || proposal.Plan.BucketSeconds != 90 || proposal.Display == nil || proposal.Display.TimeStyle != "horizon" || proposal.Display.HorizonScale != "lane" || proposal.Display.ChartsPerRow != 4 || !proposal.Display.TotalOverlay || !proposal.Display.SyncAxes || !proposal.Display.OneChartPerSeries {
		t.Fatal("filter/display composition lost", proposal.Status)
	}
	if proposal.Plan.Filter.Conditions[0].Values[0] != "18446744073709551615" {
		t.Fatal("filter counter rounded")
	}
	literal := planFlowQuestion(t, `show bps where src_as_name equals "DROP TABLE users; tenant_id=other"`, nil)
	if literal.Status != FlowQuestionReady || literal.Plan.Filter.Conditions[0].Values[0] != "DROP TABLE users; tenant_id=other" {
		t.Fatal("quoted literal interpreted as a command")
	}
}

func TestBuiltinFlowQuestionFollowupRetainsExplicitParentWithoutMutation(t *testing.T) {
	parent := planFlowQuestion(t, `show avg bps by source IP where src_port equals 443 over last 10 days all rows compare with previous period`, nil)
	if parent.Status != FlowQuestionReady {
		t.Fatal("parent question not ready")
	}
	before, err := NormalizeFlowQuestionProposal(parent, questionClock())
	if err != nil {
		t.Fatal(err)
	}
	child := planFlowQuestion(t, `what about destination ASN as bar add p95 packets where dst_country equals "DE"`, &parent)
	if child.Status != FlowQuestionReady || child.Plan.View != "bar" || child.Plan.RowLimit != parent.Plan.RowLimit || len(child.Plan.Metrics) != 2 || child.Plan.Metrics[0].Measure != "bps" || child.Plan.Metrics[1].Calculation != "p95" || child.Plan.From != parent.Plan.From || child.Previous == nil || child.Previous.To != parent.Plan.From {
		t.Fatal("follow-up lost named context", child.Status)
	}
	if !reflect.DeepEqual(parent, before) {
		t.Fatal("child changed immutable history")
	}
	if child.Plan.PageSize != parent.Plan.PageSize {
		t.Fatal("implicit view conversion retained an invalid inherited page size")
	}
	retained := planFlowQuestion(t, `as bar page size 5000`, &parent)
	if retained.Status != FlowQuestionReady || retained.Plan.RowLimit != parent.Plan.RowLimit || retained.Plan.PageSize != 5000 {
		t.Fatal("valid chart switch truncated inherited complete details")
	}
	conflict := planFlowQuestion(t, `as bar page size 5001`, &parent)
	if conflict.Status != FlowQuestionClarify || conflict.Plan != nil {
		t.Fatal("explicit conflicting chart page size was silently changed")
	}
	cleared := planFlowQuestion(t, `clear filters without comparison as table limit 50000 page size 5000`, &child)
	if cleared.Status != FlowQuestionReady || cleared.Plan.Filter != nil || cleared.Comparison != nil || cleared.Previous != nil || cleared.Plan.RowLimit != 50000 {
		t.Fatal("explicit context changes failed", cleared.Status)
	}
}

func TestBuiltinFlowQuestionRejectsUnknownSuffixActionsAndInvalidControls(t *testing.T) {
	for _, question := range []string{
		`show bps by source IP mystery-clause`, `show bps and`, `show bps? limit 50000`,
		`show bps limit 0`, `show bps page size 0`, `show bps series 0`, `show bps matrix depth 0`, `show bps charts per row 0`,
		`show bps limit 2147483648`, `show bps every 0 seconds`, `show bps every 1e99999999999999 seconds`,
		`show bps by tenant_id`, `show bps by source IP using arbitrary-table`, `show bps from 2026-10-30 to 2026-10-29`,
		`show bps ipv4 prefix /33`, `show bps ipv6 prefix /129`,
	} {
		proposal := planFlowQuestion(t, question, nil)
		if proposal.Status == FlowQuestionReady || proposal.Plan != nil {
			t.Fatal("unknown/invalid clause fell back to a partial query", question)
		}
	}
	for _, question := range []string{`DROP TABLE flows`, `delete interface 1`, `show bps; approve remediation`, `show bps; SELECT * FROM flows`} {
		proposal := planFlowQuestion(t, question, nil)
		if proposal.Status != FlowQuestionRefused || proposal.Plan != nil {
			t.Fatal("action/SQL question did not refuse", question, proposal.Status)
		}
	}
}

func TestBuiltinFlowQuestionConcurrentUseAndCancellation(t *testing.T) {
	planner, err := NewBuiltinFlowQuestionPlanner(DefaultFlowQuestionBudget())
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			proposal, err := planner.Plan(t.Context(), FlowQuestionInput{Question: "show bps by source IP", Now: questionClock()})
			if err != nil || proposal.Status != FlowQuestionReady {
				t.Error("immutable shared planner failed", err)
			}
		})
	}
	workers.Wait()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := planner.Plan(ctx, FlowQuestionInput{Question: "show bps", Now: questionClock()}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled planner ran", err)
	}
	if _, err := NewBuiltinFlowQuestionPlanner(FlowQuestionBudget{}); !errors.Is(err, ErrFlowQuestionBudget) {
		t.Fatal("invalid operator budget allowed")
	}
}

func TestBuiltinFlowQuestionCalendarAndExplicitPreviousPeriods(t *testing.T) {
	proposal := planFlowQuestion(t, `show p99 bps from 2025-01-01T01:02:03.123456789+05:30 to 2026-01-01T00:00:00Z compare with from 2020-02-01 to 2020-03-01`, nil)
	if proposal.Status != FlowQuestionReady || proposal.Plan.From.Nanosecond() != 123456789 || proposal.Previous == nil || proposal.Previous.From.Year() != 2020 || proposal.Previous.To.Month() != time.March {
		t.Fatal("arbitrary current/previous period lost", proposal.Status)
	}
	planner, _ := NewBuiltinFlowQuestionPlanner(DefaultFlowQuestionBudget())
	for _, tc := range []struct {
		question      string
		now, from, to time.Time
	}{
		{"show bps last month", time.Date(2024, 3, 31, 12, 0, 0, 123, time.UTC), time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)},
		{"show bps last 1 months", time.Date(2024, 3, 31, 12, 0, 0, 123, time.UTC), time.Date(2024, 2, 29, 12, 0, 0, 123, time.UTC), time.Date(2024, 3, 31, 12, 0, 0, 123, time.UTC)},
		{"show bps yesterday", time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC), time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)},
	} {
		proposal, err := planner.Plan(t.Context(), FlowQuestionInput{Question: tc.question, Now: tc.now, TimeZone: "UTC"})
		if err != nil || proposal.Status != FlowQuestionReady || proposal.Plan.From != tc.from || proposal.Plan.To != tc.to {
			t.Fatal("calendar semantics changed", tc.question, proposal.Status, err)
		}
	}
	location, _ := time.LoadLocation("America/New_York")
	for _, day := range []struct {
		month     time.Month
		day, hour int
	}{{time.March, 8, 2}, {time.November, 1, 1}} {
		if _, err := questionWallTime(2026, day.month, day.day, day.hour, 30, 0, 0, location); err == nil {
			t.Fatal("nonexistent/ambiguous DST wall time guessed")
		}
	}
}
