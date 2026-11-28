// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package alert_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestShippedAlertTagFilterFollowsCurrentOwnedTests(t *testing.T) {
	st := shipped.Start(t, shipped.Options{Name: "alerttag", TenantBand: 3, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "tag-receipt-testsync.pem"),
		"PROBECTL_ALERT_EVAL_INTERVAL":       evalInterval.String(),
	}})
	operator := st.OnboardOperator(t, "root@msp-tag-alert.example")
	run := strconv.FormatInt(time.Now().UnixNano(), 36)
	type lane struct {
		alertTenant
		decoy                        alertTenant
		contextID, tagID, assignment string
		rule                         alertRuleRef
	}
	var lanes [2]lane
	call := func(tenant *lane, method, path string, body, out any, want int) {
		t.Helper()
		got, raw := st.Do(t, tenant.cookie, method, path, body)
		if got != want {
			t.Fatalf("%s %s as %s: HTTP %d, want %d: %.400s", method, path, tenant.slug, got, want, raw)
		}
		if out != nil && json.Unmarshal(raw, out) != nil {
			t.Fatalf("%s %s returned invalid JSON", method, path)
		}
	}
	assign := func(tenant *lane, testID string) string {
		t.Helper()
		var assignment struct{ ID string }
		call(tenant, http.MethodPost, "/v1/entity-contexts/"+tenant.contextID+"/tag-assignments", map[string]string{
			"tag_id": tenant.tagID, "target_kind": "test", "target_id": testID, "value": "selected",
		}, &assignment, http.StatusCreated)
		if assignment.ID == "" {
			t.Fatal("the manual tag assignment has no owned ID")
		}
		return assignment.ID
	}
	probe := func(tenant *lane, testID string) (float64, bool) {
		return promValue(t, fmt.Sprintf(`max(%s{tenant_id=%q,test_id=%q})`, alertMetric, tenant.id, testID))
	}
	for i := range lanes {
		tenant := &lanes[i]
		tenant.mark = fmt.Sprintf("tag-alert-%d-%s", i, run)
		tenant.slug, tenant.name = tenant.mark, "Tagged alert "+tenant.mark
		tenant.model = []string{"pooled", "hybrid"}[i]
		tenant.admin = []string{"ada@acme.example", "bob@globex.example"}[i]
		var row struct{ ID string }
		st.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &row, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":%q}`, tenant.slug, tenant.name, tenant.model))
		tenant.id = row.ID
		tenant.cookie = st.SignIn(t, tenant.id, tenant.admin, tenant.name)
		tenant.agent = uuid.NewString()
		identity := st.EnrollAgent(t, tenant.id, tenant.agent, tenant.mark)
		st.StartAgent(t, identity, tenant.mark, []string{"tcp"}, "test_sync:\n  enabled: true\n  interval: 2s\n  allowed_types: [tcp]\n  allow_private_targets: true\n")
		tenant.target = newFlapTarget(t)
		tenant.testID = tenant.createTCPTest(t, st)
		tenant.decoy = alertTenant{mark: tenant.mark + "-decoy", slug: tenant.slug, cookie: tenant.cookie, target: newFlapTarget(t)}
		tenant.decoy.testID = tenant.decoy.createTCPTest(t, st)
		var context struct {
			ID string `json:"context_id"`
		}
		call(tenant, http.MethodPost, "/v1/entity-contexts", map[string]string{"site_label": "Alert site", "vrf_label": "Alert VRF"}, &context, http.StatusCreated)
		tenant.contextID = context.ID
		for _, testID := range []string{tenant.testID, tenant.decoy.testID} {
			call(tenant, http.MethodPut, "/v1/tests/"+testID+"/entity-context", map[string]string{"context_id": context.ID}, nil, http.StatusOK)
			shipped.Await(t, "healthy shipped probe for "+tenant.slug, 60*time.Second, func() bool {
				current, ok := probe(tenant, testID)
				return ok && current == 1
			})
		}
		var tag struct{ ID string }
		call(tenant, http.MethodPost, "/v1/tags", map[string]string{"key": "customer"}, &tag, http.StatusCreated)
		tenant.tagID = tag.ID
		tenant.assignment = assign(tenant, tenant.testID)
		tenant.rule.Name = "Current tagged probe " + tenant.mark
		tenant.rule.ID = tenant.createRuleAPI(t, st, tenant.rule.Name, nil)
		tenant.rules = []alertRuleRef{tenant.rule}
		call(tenant, http.MethodPut, "/v1/alerts/rules/"+tenant.rule.ID+"/tag-filter", alert.TagFilterInput{
			TargetKind: "test",
			Filter:     &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{"selected"}}}},
		}, nil, http.StatusOK)
	}

	waitForEvaluation := func(tenant *lane, testID string, state alert.EvaluationState, after int64) int64 {
		t.Helper()
		var revision int64
		shipped.Await(t, tenant.slug+" tagged evaluation "+string(state), 45*time.Second, func() bool {
			var out struct {
				Items []alert.EvaluationReceipt
			}
			call(tenant, http.MethodGet, "/v1/alerts/"+tenant.rule.ID+"/evaluations?limit=100", nil, &out, http.StatusOK)
			for _, row := range out.Items {
				if row.RuleID != tenant.rule.ID {
					t.Fatal("evaluation returned a foreign rule")
				}
				if row.Labels["test_id"] != testID || row.State != state || row.TagSelection == nil || row.TagSelection.Validate() != nil {
					continue
				}
				current, err := strconv.ParseInt(row.TagSelection.TagRevision, 10, 64)
				if err == nil && current > after {
					revision = current
					return true
				}
			}
			return false
		})
		return revision
	}

	owner, sibling := &lanes[0], &lanes[1]
	before := waitForEvaluation(owner, owner.testID, "normal", 0)
	waitForEvaluation(sibling, sibling.testID, "normal", 0)
	for i := range lanes {
		tenant := &lanes[i]
		tenant.decoy.target.down(t)
		shipped.Await(t, "unselected failing probe for "+tenant.slug, 60*time.Second, func() bool {
			current, ok := probe(tenant, tenant.decoy.testID)
			return ok && current == 0
		})
	}

	assign(owner, owner.decoy.testID)
	call(owner, http.MethodDelete, "/v1/entity-contexts/"+owner.contextID+"/tag-assignments/"+owner.assignment, nil, nil, http.StatusNoContent)
	waitForEvaluation(owner, owner.decoy.testID, "firing", before)
	for i, allowed := range []string{owner.decoy.testID, ""} {
		tenant := &lanes[i]
		active := tenant.active(t, st)
		if allowed == "" {
			if len(active) != 0 {
				t.Fatal("the sibling's failed but unselected probe raised an alert")
			}
		} else if len(active) != 1 || active[0].RuleID != tenant.rule.ID || active[0].Labels["test_id"] != allowed {
			t.Fatal("tag reassignment did not select exactly the owned failing probe", active)
		}
		call(tenant, http.MethodGet, "/v1/alerts/"+lanes[1-i].rule.ID+"/evaluations", nil, nil, http.StatusNotFound)
	}
}
