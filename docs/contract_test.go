// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package docs holds the gates that keep shipped documentation and the shipped
// product contract in step with the code.
//
// These tests used to read a planning document that lived beside the repository
// rather than inside it, and most of what they asserted was that document's
// WORDING. The authority is now contract/product-contract.json: committed with
// the code, machine-readable, and therefore checkable in CI on a plain checkout.
// Assertions that could only ever be about planning prose were removed rather
// than re-pointed at something that would make them look like they still held.
package docs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type contractFeature struct {
	IDs      []string `json:"ids"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Evidence string   `json:"evidence"`
}

type productContract struct {
	Schema   string            `json:"schema"`
	Purpose  string            `json:"purpose"`
	Features []contractFeature `json:"features"`
	Planes   []struct {
		Plane  string `json:"plane"`
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"planes"`
	Verification struct {
		WorkflowJobs       int    `json:"workflow_jobs"`
		WorkflowJobsSource string `json:"workflow_jobs_source"`
		RCAEval            struct {
			Blocking               bool    `json:"blocking"`
			AnswerAccuracyFloor    float64 `json:"answer_accuracy_floor"`
			CitationPrecisionFloor float64 `json:"citation_precision_floor"`
		} `json:"rca_eval"`
	} `json:"verification"`
	ParkedExternalProofs []struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	} `json:"parked_external_proofs"`
}

func readContract(t *testing.T) productContract {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("contract", "product-contract.json"))
	if err != nil {
		t.Fatalf("read product contract: %v", err)
	}
	var c productContract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse product contract: %v", err)
	}
	return c
}

func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestProductContractIsWellFormed is the non-vacuity guard. Every test below
// compares something real against this file, so a contract that parsed to an
// empty struct would make all of them pass by checking nothing.
func TestProductContractIsWellFormed(t *testing.T) {
	t.Parallel()
	c := readContract(t)
	if c.Schema != "probectl.product-contract/v1" {
		t.Fatalf("unexpected schema %q", c.Schema)
	}
	if len(c.Features) < 50 {
		t.Fatalf("only %d features in the contract — it is truncated or the parse broke", len(c.Features))
	}
	if len(c.Planes) != 5 {
		t.Fatalf("probectl ships five telemetry planes, the contract declares %d", len(c.Planes))
	}
	valid := map[string]bool{"delivered": true, "partial": true, "future": true, "removed": true}
	seen := map[string]string{}
	for _, f := range c.Features {
		if !valid[f.Status] {
			t.Errorf("feature %v has unknown status %q", f.IDs, f.Status)
		}
		if strings.TrimSpace(f.Name) == "" {
			t.Errorf("feature %v has no name", f.IDs)
		}
		if len(f.IDs) == 0 {
			t.Errorf("feature %q declares no ids", f.Name)
		}
		for _, id := range f.IDs {
			if prev, dup := seen[id]; dup {
				t.Errorf("feature id %s is claimed by both %q and %q", id, prev, f.Name)
			}
			seen[id] = f.Name
		}
	}
	for _, p := range c.Planes {
		if !valid[p.Status] {
			t.Errorf("plane %q has unknown status %q", p.Name, p.Status)
		}
	}
}

// TestWorkflowJobCountMatchesWorkflows keeps the advertised size of the
// verification net honest: the number in the contract is what the counter
// actually finds in .github/workflows/.
func TestWorkflowJobCountMatchesWorkflows(t *testing.T) {
	t.Parallel()
	c := readContract(t)
	out, err := exec.Command("python3", filepath.Join("..", "scripts", "count_workflow_jobs.py"), "--total").Output()
	if err != nil {
		t.Fatalf("count workflow jobs: %v", err)
	}
	counted := strings.TrimSpace(string(out))
	if got := strconv.Itoa(c.Verification.WorkflowJobs); got != counted {
		t.Fatalf("contract claims %s workflow jobs, %s finds %s", got, c.Verification.WorkflowJobsSource, counted)
	}
	if c.Verification.WorkflowJobs < 20 {
		t.Fatalf("workflow job count %d is implausibly low — the counter probably matched nothing", c.Verification.WorkflowJobs)
	}
}

// TestRCAEvalContractMatchesBlockingCI keeps the contract's RCA-eval floors and
// the CI job that enforces them from drifting apart. The floors are the claim;
// ci.yml is the enforcement.
func TestRCAEvalContractMatchesBlockingCI(t *testing.T) {
	t.Parallel()
	c := readContract(t)
	ci := readDoc(t, filepath.Join("..", ".github", "workflows", "ci.yml"))

	if !c.Verification.RCAEval.Blocking {
		t.Fatal("the contract declares RCA eval non-blocking; CI enforces it, so the contract is wrong")
	}
	for _, stale := range []string{
		"non-blocking CI job uploads the score artifact",
		"*rca-eval* (non-blocking)",
	} {
		if strings.Contains(ci, stale) {
			t.Fatalf("ci.yml still contains stale non-blocking RCA eval wording %q", stale)
		}
	}
	for _, want := range []string{
		"rca-eval (BLOCKING",
		"answer_accuracy >= " + ftoa(c.Verification.RCAEval.AnswerAccuracyFloor) +
			" AND citation_precision >= " + ftoa(c.Verification.RCAEval.CitationPrecisionFloor),
	} {
		if !strings.Contains(ci, want) {
			t.Fatalf("ci.yml does not enforce the contract's RCA eval floors: missing %q", want)
		}
	}
}

// ftoa renders a floor the way ci.yml writes it (0.85, not 0.850000).
func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// TestParkedExternalProofsStayDeclared keeps the four proofs probectl cannot run
// in this lab visible and honest. Losing this declaration is how a parked proof
// quietly becomes an implied pass.
func TestParkedExternalProofsStayDeclared(t *testing.T) {
	t.Parallel()
	c := readContract(t)
	want := map[string]bool{"E2": false, "E3": false, "E4": false, "L4": false}
	for _, p := range c.ParkedExternalProofs {
		if _, ok := want[p.ID]; !ok {
			t.Errorf("unexpected parked proof %q", p.ID)
			continue
		}
		want[p.ID] = true
		if strings.TrimSpace(p.Reason) == "" {
			t.Errorf("parked proof %s has no reason — a parked proof without a reason reads as an oversight", p.ID)
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("parked external proof %s is no longer declared; it must stay visible until it is actually run", id)
		}
	}
}

// TestF49MarketplaceStaysOutsideGA keeps the one deliberate future bet from
// being recounted as a GA gap or quietly promoted. The surface side of this
// contract is asserted by web/src/test/surface-coverage.test.tsx.
func TestF49MarketplaceStaysOutsideGA(t *testing.T) {
	t.Parallel()
	c := readContract(t)
	var found bool
	for _, f := range c.Features {
		for _, id := range f.IDs {
			if id != "F49" {
				continue
			}
			found = true
			if f.Status != "future" {
				t.Fatalf("F49 %q is %q in the contract; it is a declared future bet, not GA work", f.Name, f.Status)
			}
		}
	}
	if !found {
		t.Fatal("F49 has left the contract entirely — it must stay in the traceability denominator as an explicit future bet")
	}
}

func TestAlertEvaluatorDocsMatchSupervisorAndPromQuery(t *testing.T) {
	arch := readDoc(t, "architecture.md")
	alerting := readDoc(t, "alerting.md")
	feature := readDoc(t, filepath.Join("features", "alerting-and-incidents.md"))
	all := strings.Join([]string{arch, alerting, feature}, "\n")

	for _, stale := range []string{
		"Today's wiring evaluates the\ndefault tenant over the in-process TSDB",
		"per-tenant fan-out across many tenants is a\nnoted follow-up",
		"Prometheus query backend are follow-ups",
		"no in-process metric query backend wired",
	} {
		if strings.Contains(all, stale) {
			t.Fatalf("alert docs still contain stale evaluator wording %q", stale)
		}
	}
	for _, want := range []string{
		"AlertEvaluatorSupervisor",
		"one evaluator engine per active tenant",
		"Prometheus/VictoriaMetrics instant-query backend",
		"forced `tenant_id` matcher",
		"neither an in-process TSDB nor a Prometheus/VictoriaMetrics instant-query",
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("alert docs missing current evaluator wording %q", want)
		}
	}
}

// TestDocsAdvertiseCLIOnlyUntilTUIExists keeps the shipped documentation from
// promising a terminal UI that does not exist. The planning document this once
// also checked has left the repository; the assertions below are the ones whose
// subject is a document probectl actually ships.
func TestDocsAdvertiseCLIOnlyUntilTUIExists(t *testing.T) {
	features := readDoc(t, "features.md")
	controlPlane := readDoc(t, filepath.Join("features", "control-plane.md"))
	configuration := readDoc(t, "configuration.md")
	all := strings.Join([]string{features, controlPlane, configuration}, "\n")

	for _, stale := range []string{
		"CLI" + "/" + "TUI",
		"command-line interface and terminal " + "UI",
		"The terminal " + "UI is the keyboard-first companion",
		"`probectl` CLI / terminal " + "UI",
	} {
		if strings.Contains(all, stale) {
			t.Fatalf("terminal surface docs still contain stale TUI promise %q", stale)
		}
	}
	for _, want := range []string{
		"F10 — Control plane (REST/gRPC + CLI)",
		"a **command-line interface** (`probectl`)",
		"The terminal-native product surface is the CLI",
		"There is no separate committed TUI " + "mode today",
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("terminal surface docs missing CLI-only wording %q", want)
		}
	}
}
