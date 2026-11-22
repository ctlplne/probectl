// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
)

type syntheticDDoSReplayWindow struct {
	From     time.Time           `json:"from"`
	To       time.Time           `json:"to"`
	Complete bool                `json:"complete"`
	Flows    []flowstore.PlanRow `json:"flows"`
	HTTP     []otelstore.Span    `json:"http"`
}

type syntheticDDoSReplayPair struct {
	Reference syntheticDDoSReplayWindow `json:"reference"`
	Current   syntheticDDoSReplayWindow `json:"current"`
}

type syntheticDDoSReplayTrial struct {
	ID           string                     `json:"id"`
	ModeledStart time.Time                  `json:"modeled_start"`
	Scope        flow.DDoSAssessmentInput   `json:"scope"`
	Pairs        [2]syntheticDDoSReplayPair `json:"pairs"`
}

type syntheticDDoSTruth struct {
	ID       string `json:"id"`
	Scenario string `json:"scenario"`
	Positive bool   `json:"positive"`
}

type syntheticDDoSReplayInputs struct {
	Schema     string                     `json:"schema"`
	RowsSHA256 string                     `json:"fixture_rows_sha256"`
	Cases      []syntheticDDoSReplayTrial `json:"cases"`
}

type syntheticDDoSReplayTruth struct {
	InputsSHA256 string               `json:"inputs_sha256"`
	Cases        []syntheticDDoSTruth `json:"cases"`
}

type syntheticDDoSDecision struct {
	ID             string `json:"id"`
	Decision       string `json:"decision"`
	EpisodeDelayMS *int   `json:"episode_delay_ms,omitempty"`
}

type syntheticDDoSReplayDecisions struct {
	Schema       string                  `json:"schema"`
	InputsSHA256 string                  `json:"inputs_sha256"`
	Cases        []syntheticDDoSDecision `json:"cases"`
}

func syntheticDDoSDecisionFor(id string, outcome benchmarkDDoSOutcome) syntheticDDoSDecision {
	decision := syntheticDDoSDecision{ID: id, Decision: "quiet"}
	switch {
	case outcome.Abstained:
		decision.Decision = "abstained"
	case outcome.Class != "":
		delayMS := outcome.DelaySeconds * 1000
		decision.Decision, decision.EpisodeDelayMS = "episode", &delayMS
	}
	return decision
}

func syntheticDDoSRowsDigest(cases []syntheticDDoSReplayTrial) (string, error) {
	flows := make([][]flowstore.PlanRow, 0, len(cases)*4)
	application := make([][]otelstore.Span, 0, len(cases)*3)
	for _, trial := range cases {
		for _, pair := range trial.Pairs {
			flows = append(flows, pair.Reference.Flows, pair.Current.Flows)
			if trial.Scope.Application != nil {
				application = append(application, pair.Reference.HTTP, pair.Current.HTTP)
			}
		}
	}
	evidence, err := json.Marshal(struct {
		Flows       [][]flowstore.PlanRow
		Application [][]otelstore.Span
	}{flows, application})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(evidence)), nil
}

func writeSyntheticDDoSReplay(dir string, cases []syntheticDDoSReplayTrial, truth []syntheticDDoSTruth, decisions []syntheticDDoSDecision, rowsDigest string) error {
	inputs, err := json.Marshal(syntheticDDoSReplayInputs{
		Schema: "probectl-ddos-synthetic-replay-v1", RowsSHA256: rowsDigest, Cases: cases,
	})
	if err != nil {
		return err
	}
	inputHash := hex.EncodeToString(crypto.Hash(inputs))
	answers, err := json.Marshal(syntheticDDoSReplayTruth{InputsSHA256: inputHash, Cases: truth})
	if err != nil {
		return err
	}
	results, err := json.Marshal(syntheticDDoSReplayDecisions{
		Schema: "probectl-ddos-synthetic-decisions-v1", InputsSHA256: inputHash, Cases: decisions,
	})
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "inputs.json"), inputs, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ground-truth.json"), answers, 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "probectl-decisions.json"), results, 0600)
}

func materializeSyntheticDDoSReplay(index int, trial benchmarkDDoSTrial) (syntheticDDoSReplayTrial, error) {
	end := benchmarkDDoSEpoch.Add(2 * time.Duration(trial.Settings.PeriodSeconds) * time.Second)
	clocks, err := ddosClocks(end, trial.Settings.PeriodSeconds)
	if err != nil {
		return syntheticDDoSReplayTrial{}, err
	}
	replay := syntheticDDoSReplayTrial{ID: fmt.Sprintf("trial-%04d", index), Scope: trial.Settings,
		ModeledStart: benchmarkDDoSEpoch.Add(-time.Duration(trial.OnsetBeforeAligned) * time.Second)}
	for i, pair := range []anomaly.FlowFieldComparisonClocks{clocks.Previous, clocks.Current} {
		replay.Pairs[i] = syntheticDDoSReplayPair{
			Reference: syntheticDDoSWindow(pair.Before, trial.Reference, trial.Settings.Application != nil),
			Current:   syntheticDDoSWindow(pair.After, trial.Windows[i], trial.Settings.Application != nil),
		}
	}
	return replay, nil
}

func syntheticDDoSWindow(clocks anomaly.TrainingWindow, window benchmarkDDoSWindow, includeHTTP bool) syntheticDDoSReplayWindow {
	result := syntheticDDoSReplayWindow{
		From: clocks.Start, To: clocks.End, Complete: window.Complete, Flows: benchmarkDDoSRows(window),
	}
	if includeHTTP {
		result.HTTP = benchmarkDDoSAppSpans(window.Application, clocks.Start)
	}
	return result
}

func TestSyntheticDDoSReplayExport(t *testing.T) {
	var cases []syntheticDDoSReplayTrial
	var truth []syntheticDDoSTruth
	var decisions []syntheticDDoSDecision
	for _, trial := range benchmarkDDoSFixture() {
		if trial.Name != "volume_health_drop/00" && trial.Name != "matched_flash_crowd/00" {
			continue
		}
		replay, err := materializeSyntheticDDoSReplay(len(cases)+1, trial)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, replay)
		positive := trial.Family == "volume_health_drop"
		truth = append(truth, syntheticDDoSTruth{ID: replay.ID, Scenario: trial.Name, Positive: positive})
		outcome := benchmarkDDoSOutcome{}
		if positive {
			outcome.Class, outcome.DelaySeconds = anomaly.DDoSVolumetric, 10
		}
		decisions = append(decisions, syntheticDDoSDecisionFor(replay.ID, outcome))
	}
	if len(cases) != 2 {
		t.Fatal("expected both matched synthetic cases")
	}
	digest, err := syntheticDDoSRowsDigest(cases)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "replay")
	if err := writeSyntheticDDoSReplay(dir, cases, truth, decisions, digest); err != nil {
		t.Fatal(err)
	}
	inputs, err := os.ReadFile(filepath.Join(dir, "inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var replay syntheticDDoSReplayInputs
	if err := json.Unmarshal(inputs, &replay); err != nil || len(replay.Cases) != 2 ||
		bytes.Contains(inputs, []byte(`"positive":`)) || bytes.Contains(inputs, []byte(`"scenario":`)) {
		t.Fatal("replay blobs must include both cases with separate ground truth", err)
	}
	if got, err := syntheticDDoSRowsDigest(replay.Cases); err != nil || got != digest || replay.RowsSHA256 != digest {
		t.Fatal("exported windows changed the observed rows or their digest", got, err)
	}
	answers, err := os.ReadFile(filepath.Join(dir, "ground-truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var labels syntheticDDoSReplayTruth
	if err := json.Unmarshal(answers, &labels); err != nil || len(labels.Cases) != 2 ||
		labels.InputsSHA256 != hex.EncodeToString(crypto.Hash(inputs)) ||
		labels.Cases[0] != truth[0] || labels.Cases[1] != truth[1] ||
		labels.Cases[0].ID != replay.Cases[0].ID || labels.Cases[1].ID != replay.Cases[1].ID {
		t.Fatal("ground truth must identify its input and each trial", err)
	}
	resultBody, err := os.ReadFile(filepath.Join(dir, "probectl-decisions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result syntheticDDoSReplayDecisions
	if err := json.Unmarshal(resultBody, &result); err != nil || result.Schema != "probectl-ddos-synthetic-decisions-v1" ||
		result.InputsSHA256 != labels.InputsSHA256 || len(result.Cases) != 2 {
		t.Fatal("decisions must bind to the original input", err)
	}
	episode, quiet := result.Cases[0], result.Cases[1]
	if episode.ID != replay.Cases[0].ID || episode.Decision != "episode" || episode.EpisodeDelayMS == nil || *episode.EpisodeDelayMS != 10000 ||
		quiet.ID != replay.Cases[1].ID || quiet.Decision != "quiet" || quiet.EpisodeDelayMS != nil {
		t.Fatal("decisions lost the episode clock or quiet control", result)
	}
	if err := writeSyntheticDDoSReplay(dir, cases, truth, decisions, digest); !errors.Is(err, os.ErrExist) {
		t.Fatal("export accepted an existing destination", err)
	}
}
