// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type subscriberLane struct {
	*nativeLane
	tagID, contextID, alphaAssignment string
	alphaTarget                       string
}

func TestShippedSubscriberUsageReconcilesOverlappingTenantAndSubscriberScopes(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "subscriberusage", TenantBand: 3})
	operator := stack.OnboardOperator(t, "root@msp-subscriber-usage.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := []subscriberLane{{nativeLane: &nativeLane{name: "red", octet: 184}}, {nativeLane: &nativeLane{name: "blue", octet: 184}}}
	for i := range lanes {
		lanes[i].provision(t, stack, operator, run)
		lanes[i].configureSubscribers(t, stack)
	}
	from := time.Now().UTC().Truncate(time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	for i, lane := range lanes {
		lane.sendSubscriberRecords(t, uint64(i+1))
	}
	time.Sleep(5 * time.Millisecond)
	to := time.Now().UTC()
	var refs [2]flow.SavedQueryView
	for i, lane := range lanes {
		want := uint64(i + 1)
		refs[i] = lane.waitAndSaveSubscriberView(t, stack, from, to, want*3000)
		assertSubscriberLaneUsage(t, stack, lane, refs[i], "alpha", want*1000, want*40)
		assertSubscriberLaneUsage(t, stack, lane, refs[i], "beta", want*2000, want*60)
	}
	for i, lane := range lanes {
		other := lanes[1-i]
		foreign := flow.SubscriberUsageRequest{Version: refs[1-i].Version, TagID: other.tagID, TagKey: "subscriber", Subscriber: "alpha"}
		lane.do(t, stack, http.MethodPost, subscriberUsagePath(refs[1-i].ID), foreign, nil, http.StatusNotFound)
		foreign.Version = refs[i].Version
		lane.do(t, stack, http.MethodPost, subscriberUsagePath(refs[i].ID), foreign, nil, http.StatusNotFound)
	}
	proveSubscriberUsageConsole(t, stack, lanes[0], refs[0])
	lanes[0].do(t, stack, http.MethodPut, "/v1/entity-contexts/"+lanes[0].contextID+"/tag-assignments/"+lanes[0].alphaAssignment,
		map[string]string{"tag_id": lanes[0].tagID, "target_kind": "prefix", "target_id": lanes[0].alphaTarget, "value": "next-subscriber"}, nil, http.StatusOK)
	lanes[0].do(t, stack, http.MethodPost, subscriberUsagePath(refs[0].ID), flow.SubscriberUsageRequest{
		Version: refs[0].Version, TagID: lanes[0].tagID, TagKey: "subscriber", Subscriber: "next-subscriber",
	}, nil, http.StatusConflict)
}

func (l *subscriberLane) configureSubscribers(t *testing.T, st *shipped.Stack) {
	t.Helper()
	var context entity.ContextRecord
	l.do(t, st, http.MethodPost, "/v1/entity-contexts", map[string]string{"site_label": "Subscriber lab", "vrf_label": "Subscriber service"}, &context, http.StatusCreated)
	l.contextID = context.ContextID
	l.do(t, st, http.MethodPut, "/v1/entity-source-contexts", map[string]string{
		"context_id": context.ContextID, "agent_id": l.agent, "source_kind": "flow_exporter", "source_ref": "127.0.0.1",
	}, nil, http.StatusOK)
	var tag struct{ ID string }
	l.do(t, st, http.MethodPost, "/v1/tags", map[string]string{"key": "subscriber"}, &tag, http.StatusCreated)
	l.tagID = tag.ID
	for i, key := range []string{"alpha", "beta"} {
		var scope entity.Record
		l.do(t, st, http.MethodPost, "/v1/entities", map[string]string{
			"context_id": context.ContextID, "kind": "prefix", "label": key, "network_prefix": fmt.Sprintf("10.%d.%d.0/24", l.octet, i+1),
		}, &scope, http.StatusCreated)
		var assignment store.TagAssignmentRecord
		l.do(t, st, http.MethodPost, "/v1/entity-contexts/"+context.ContextID+"/tag-assignments", map[string]string{
			"tag_id": tag.ID, "target_kind": "prefix", "target_id": scope.ID, "value": key,
		}, &assignment, http.StatusCreated)
		if i == 0 {
			l.alphaAssignment, l.alphaTarget = assignment.ID, scope.ID
		}
	}
}

func (l *subscriberLane) sendSubscriberRecords(t *testing.T, multiplier uint64) {
	t.Helper()
	export, err := net.Dial("udp", l.listeners["IPFIX"])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = export.Close() }()
	for i, amount := range []uint64{100, 200} {
		record := controlledTrafficIPFIX(t, l.octet, i, 0, 901+i, time.Now().UTC(), trafficVector{transport: 6, port: 41000}, amount*multiplier, uint64(i*2+4)*multiplier)
		if n, err := export.Write(record); err != nil || n != len(record) {
			t.Fatal("the synthetic subscriber observation did not reach the loopback exporter", err)
		}
	}
}

func (l *subscriberLane) waitAndSaveSubscriberView(t *testing.T, st *shipped.Stack, from, to time.Time, bytes uint64) flow.SavedQueryView {
	t.Helper()
	plan := nativeGoldenPlan(l.octet, to, []string{"dst_addr"})
	plan.From, plan.To, plan.DataSeries = from, to, "raw"
	shipped.Await(t, "exact subscriber observations have reached the tenant store", 30*time.Second, func() bool {
		code, raw := st.Do(t, l.cookie, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan})
		var found struct{ Flow flowstore.PlanResult }
		return code == http.StatusOK && json.Unmarshal(raw, &found) == nil && found.Flow.Totals["bytes:total"] == strconv.FormatUint(bytes, 10)
	})
	var saved flow.SavedQueryView
	l.do(t, st, http.MethodPost, "/v1/explorer/flow-views", map[string]any{"definition": flow.QueryViewDefinition{
		Name: "Subscriber lab usage", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, Plan: plan,
	}}, &saved, http.StatusCreated)
	return saved
}

func subscriberUsagePath(id string) string {
	return "/v1/explorer/flow-views/" + id + "/subscriber-usage"
}

func assertSubscriberLaneUsage(t *testing.T, st *shipped.Stack, lane subscriberLane, view flow.SavedQueryView, value string, bytes, packets uint64) {
	t.Helper()
	input := flow.SubscriberUsageRequest{Version: view.Version, TagID: lane.tagID, TagKey: "subscriber", Subscriber: value}
	var report flow.SubscriberUsageReport
	lane.do(t, st, http.MethodPost, subscriberUsagePath(view.ID), input, &report, http.StatusOK)
	want := flow.SubscriberTraffic{Bytes: strconv.FormatUint(bytes, 10), Packets: strconv.FormatUint(packets, 10)}
	if report.Subscriber != value || report.TagID != lane.tagID || report.Total != want || report.Download != want || report.Upload.Bytes != "0" ||
		len(report.TopServices) != 1 || report.TopServices[0].Status != "unknown" || report.TopServices[0].Traffic != want {
		t.Fatalf("subscriber usage did not reconcile the original scoped counters: %+v", report)
	}
	var fromCLI flow.SubscriberUsageReport
	st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": lane.apiToken}, &fromCLI, "explorer", "subscriber-usage", view.ID, "--body-file", st.SecretFile(t, input))
	if fromCLI.Total != want || fromCLI.TagRevision != report.TagRevision {
		t.Fatal("CLI did not preserve the exact subscriber report")
	}
}

func proveSubscriberUsageConsole(t *testing.T, st *shipped.Stack, lane subscriberLane, view flow.SavedQueryView) {
	t.Helper()
	for _, theme := range []string{"light", "dark"} {
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: st.BaseURL + "/ui/explore?flow_view=" + view.ID, TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Accessibility: true, Theme: theme,
			Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}}, Expect: []string{"Subscriber usage"},
			Steps: []testsupport.RenderStep{
				{Click: "Open subscriber usage", Expect: []string{"Subscriber prefix tag"}},
				{Select: "label:text-is('Subscriber prefix tag') + div select", Value: lane.tagID},
				{Fill: "label:text-is('Subscriber tag value') + div input", Value: "alpha"},
				{Click: "Run subscriber report", Expect: []string{"Observed usage for alpha", "1000 bytes", "Remote services"}},
			},
		})
	}
}
