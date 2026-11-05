// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/config"
)

func TestFlowQuestionCompositionKeepsBuiltinAndOperatorResources(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	planner, err := BuildFlowQuestionPlanner(nil, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := ai.FlowQuestionInput{Question: "show bps all rows", Now: time.Now().UTC()}
	proposal, err := planner.Plan(t.Context(), input)
	if err != nil || proposal.Plan.RowLimit != 2147483647 {
		t.Fatal("default construction did not retain native builtin reach", err)
	}
	planner, err = BuildFlowQuestionPlanner(&config.Config{FlowQuestionMaxBytes: 4}, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = planner.Plan(t.Context(), input); !errors.Is(err, ai.ErrFlowQuestionBudget) {
		t.Fatal("builtin dropped configured question policy", err)
	}
	for _, cfg := range []*config.Config{{FlowQuestionMaxBytes: -1}, {FlowQuestionModelOutputTokens: -1}, {FlowQuestionModelResponseBytes: -1}, {FlowQuestionModelTokenParameter: "arbitrary"}} {
		if _, err := BuildFlowQuestionPlanner(cfg, log, nil); !errors.Is(err, ai.ErrFlowQuestionBudget) {
			t.Fatal("invalid programmatic policy reached construction", err)
		}
	}
}

func TestFlowQuestionCompositionAppliesRealAdapterPolicy(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	socket := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Options struct {
				Tokens int `json:"num_predict"`
			} `json:"options"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Options.Tokens != 1234 {
			t.Error("configured completion policy did not reach actual TLS adapter")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"role": "assistant", "content": `{"status":"ready","plan":{}}`}, "done": true, "done_reason": "stop"})
	}))
	defer socket.Close()
	ca := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AIModelProvider: "ollama", AIModelName: "owned-fixture", AIModelEndpoint: socket.URL, AIModelCAFile: ca, FlowQuestionModelOutputTokens: 1234, FlowQuestionModelResponseBytes: 8}
	planner, err := BuildFlowQuestionPlanner(cfg, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := ai.FlowQuestionInput{Question: "show bps", Now: time.Now().UTC()}
	if _, err = planner.Plan(t.Context(), input); !errors.Is(err, ai.ErrFlowQuestionBudget) {
		t.Fatal("configured wire body policy was discarded", err)
	}
	cfg.FlowQuestionModelResponseBytes = 4096
	planner, err = BuildFlowQuestionPlanner(cfg, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	if proposal, err := planner.Plan(t.Context(), input); err != nil || proposal.Status != ai.FlowQuestionReady {
		t.Fatal("valid configured completion not served", err)
	}
}
