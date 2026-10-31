// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

func TestFlowQuestionPolicyUsesSameGateAuditsDenialAndNeverDispatches(t *testing.T) {
	for _, mode := range []string{"allowed", "denied", "policy error", "audit error", "other tenant", "other gate", "missing gate", "missing principal", "local", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			reads := 0
			var events []EgressEvent
			gate := NewEgressGate(func(_ context.Context, tenant string) (bool, error) {
				reads++
				if mode == "policy error" {
					return false, errors.New("private policy diagnostic")
				}
				return mode != "denied" && mode != "audit error" && tenant == "own", nil
			}, func(_ context.Context, event EgressEvent) error {
				events = append(events, event)
				if mode == "audit error" {
					return errors.New("private audit diagnostic")
				}
				return nil
			}, DefaultRedaction)
			inner := &flowModelFixture{remote: mode != "local"}
			planner, err := NewModelFlowQuestionPlanner(NewGatedCompleter(inner, gate), DefaultFlowQuestionBudget())
			if err != nil {
				t.Fatal(err)
			}
			shared := gate
			ctx := auth.WithPrincipal(t.Context(), &auth.Principal{TenantID: "own", UserID: "owner"})
			var want error
			switch mode {
			case "denied", "other tenant", "policy error":
				want = ErrEgressDenied
			case "audit error", "other gate", "missing gate":
				want = ErrEgressAuditUnavailable
			case "missing principal":
				ctx, want = t.Context(), ErrNoTenant
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			}
			if mode == "other tenant" {
				ctx = auth.WithPrincipal(ctx, &auth.Principal{TenantID: "blue", UserID: "blue-owner"})
			}
			if mode == "other gate" {
				shared = NewEgressGate(func(context.Context, string) (bool, error) { t.Fatal("alternate gate queried"); return true, nil }, nil, DefaultRedaction)
			}
			if mode == "missing gate" || mode == "local" {
				shared = nil
			}
			if err := planner.RevalidateFlowQuestion(ctx, shared); !errors.Is(err, want) {
				t.Fatal("current planner policy verdict changed", err)
			} else if err != nil && strings.Contains(err.Error(), "private") {
				t.Fatal("current policy returned private audit diagnostics")
			}
			calls, system, user := inner.observed()
			if calls != 0 || system != "" || user != "" {
				t.Fatal("policy recheck dispatched model content")
			}
			denied := mode == "denied" || mode == "policy error" || mode == "audit error" || mode == "other tenant"
			if denied {
				if reads != 1 || len(events) != 1 || !events[0].Denied || events[0].Surface != "flow_question" || events[0].Endpoint != inner.Endpoint() || events[0].TenantID != auth.PrincipalFrom(ctx).TenantID {
					t.Fatal("current policy denial bypassed shared tenant audit")
				}
			} else if len(events) != 0 || mode != "allowed" && reads != 0 || mode == "allowed" && reads != 1 {
				t.Fatal("local,unavailable or allowed recheck produced a false remote event", reads, len(events))
			}
		})
	}
}

func TestFlowQuestionPolicyOfflineAndUnavailableFailClosed(t *testing.T) {
	builtin, err := NewBuiltinFlowQuestionPlanner(DefaultFlowQuestionBudget())
	if err != nil || builtin.RevalidateFlowQuestion(t.Context(), nil) != nil {
		t.Fatal("offline policy acquired a remote consent dependency", err)
	}
	var missing *ModelFlowQuestionPlanner
	if err := missing.RevalidateFlowQuestion(t.Context(), nil); !errors.Is(err, ErrFlowQuestionModelUnavailable) {
		t.Fatal("missing planner acquired policy authority", err)
	}
	empty := &ModelFlowQuestionPlanner{completer: NewGatedCompleter(nil, nil)}
	if err := empty.RevalidateFlowQuestion(t.Context(), nil); !errors.Is(err, ErrFlowQuestionModelUnavailable) {
		t.Fatal("missing model classification acquired policy authority", err)
	}
}
