// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/lifecycle"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRolloutVerificationTimeoutPersistsTenantHalt(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	owner, sibling := f.tenants[0], f.tenants[1]
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permAgentRead)
		})
	}
	const id = "rollout-verification-timeout"
	path := "/v1/rollouts/" + id
	plan := &agent.RolloutPlan{Target: agent.VerifiedArtifact{
		Version: "v0.2.0", Digest: "sha256:" + strings.Repeat("a", 64), Method: "cosign verify", VerifiedBy: f.users[owner],
	}, Waves: []agent.Wave{{Cohort: lifecycle.CohortCanary, AgentIDs: []string{"unobserved-agent"}, Status: agent.WavePending}},
		VerifyWindow: time.Minute, HeartbeatSLO: time.Minute}
	if _, err := plan.Advance(time.Now().Add(-2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	var revision int64
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		raw, err := encodeRolloutPlan(plan)
		if err != nil {
			return err
		}
		stored, err := (store.Rollouts{}).Create(ctx, sc, id, raw)
		if err == nil {
			revision = stored.Revision
		}
		return err
	})
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)
	result := callSeasonalAPI(t, server, f.tokens[owner], http.MethodPost, path+"/verify", nil, http.StatusBadRequest)
	if !strings.Contains(string(result), "ROLLOUT HALTED") {
		t.Fatal("the expired verification did not report the halt transition", string(result))
	}
	var view struct {
		Halted     bool     `json:"halted"`
		Stragglers []string `json:"stragglers"`
	}
	result = callSeasonalAPI(t, server, f.tokens[owner], http.MethodGet, path, nil, http.StatusOK)
	if err := json.Unmarshal(result, &view); err != nil || !view.Halted || len(view.Stragglers) != 1 {
		t.Fatal("the recorded halt and straggler did not survive the request", view, err)
	}
	callSeasonalAPI(t, server, f.tokens[owner], http.MethodPost, path+"/advance", nil, http.StatusBadRequest)
	callSeasonalAPI(t, server, f.tokens[owner], http.MethodPost, path+"/verify", nil, http.StatusBadRequest)
	callSeasonalAPI(t, server, f.tokens[sibling], http.MethodGet, path, nil, http.StatusNotFound)
	callSeasonalAPI(t, server, f.tokens[sibling], http.MethodPost, path+"/resume", map[string]string{"reason": "fixture sibling"}, http.StatusNotFound)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var events, audit int
			if err := sc.Q.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM rollout_events WHERE rollout_id=$1 AND action='rollout.verify'),
				(SELECT count(*) FROM audit_events WHERE target=$1 AND action='rollout.verify' AND data->>'outcome'='failure')`, id).Scan(&events, &audit); err != nil {
				return err
			}
			if tenant == owner {
				stored, err := (store.Rollouts{}).Get(ctx, sc, id)
				if err != nil {
					return err
				}
				reloaded, err := decodeRolloutPlan(stored)
				if err != nil || stored.Revision != revision+1 || !reloaded.Halted || len(reloaded.Waves) != 1 ||
					reloaded.Waves[0].Status != agent.WaveHalted || events != 1 || audit != 1 {
					t.Fatal("expected exactly one persisted halt and its audit event", stored.Revision, reloaded, events, audit, err)
				}
			} else if events != 0 || audit != 0 {
				t.Fatal("the sibling could see the rollout event or tenant audit record", events, audit)
			}
			return nil
		})
	}
	callSeasonalAPI(t, server, f.tokens[owner], http.MethodPost, path+"/resume", map[string]string{"reason": "fixture operator checked the agent"}, http.StatusOK)
}
