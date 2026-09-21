// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestProductionOperationsChaosStepIsLocalEvidenceDrill(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("journeys", "production-operations.md"))
	if err != nil {
		t.Fatalf("read production-operations journey: %v", err)
	}
	body := string(doc)
	normalized := strings.Join(strings.Fields(body), " ")
	for _, want := range []string{
		"local evidence drill",
		"`make chaos-dependency-drill`",
		"`CHAOS_DEPENDENCY_RESULT`",
		"not a served production workflow",
		"not a remote chaos API",
		"does not call the control-plane API",
		"F47 remains `none-by-design`",
	} {
		if !strings.Contains(body, want) && !strings.Contains(normalized, want) {
			t.Fatalf("production operations J6.5 must document chaos as a local evidence drill: missing %q", want)
		}
	}
}

func TestJourneyMarkdownLinksResolve(t *testing.T) {
	paths := []string{"journeys.md"}
	matches, err := filepath.Glob(filepath.Join("journeys", "*.md"))
	if err != nil {
		t.Fatalf("glob journey docs: %v", err)
	}
	paths = append(paths, matches...)

	linkRE := regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	for _, path := range paths {
		doc, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, match := range linkRE.FindAllStringSubmatch(string(doc), -1) {
			target := strings.TrimSpace(match[1])
			if target == "" || strings.HasPrefix(target, "#") ||
				strings.HasPrefix(target, "http://") ||
				strings.HasPrefix(target, "https://") ||
				strings.HasPrefix(target, "mailto:") {
				continue
			}
			if idx := strings.IndexByte(target, '#'); idx >= 0 {
				target = target[:idx]
			}
			if target == "" {
				continue
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
			if _, err := os.Stat(resolved); err != nil {
				t.Fatalf("%s links to missing local target %q resolved as %s: %v", path, match[1], resolved, err)
			}
		}
	}
}

type journeyMeasurementBaseline struct {
	Measurements []struct {
		Journey              string `json:"journey"`
		PointerInteractions  int    `json:"pointer_interactions"`
		KeyboardInteractions int    `json:"keyboard_interactions"`
		ContextBreaks        int    `json:"context_breaks"`
	} `json:"measurements"`
}

type journeyRubricMeasurement struct {
	Interactions  int
	ContextBreaks int
}

func TestJourneyRubricMeasurementsMatchBaseline(t *testing.T) {
	baseline, rubric := readJourneyRubricInputs(t)
	if err := validateJourneyRubricMeasurements(baseline, rubric); err != nil {
		t.Fatal(err)
	}
}

func TestJourneyRubricMeasurementsRejectPlantedDrift(t *testing.T) {
	baseline, rubric := readJourneyRubricInputs(t)
	planted := strings.Replace(
		string(rubric),
		"| J1      | healthy producer plus named real finding                  |            4 |",
		"| J1      | healthy producer plus named real finding                  |            8 |",
		1,
	)
	if planted == string(rubric) {
		t.Fatal("plant J1 interaction drift: source row was not found")
	}
	err := validateJourneyRubricMeasurements(baseline, []byte(planted))
	if err == nil {
		t.Fatal("planted J1 interaction drift passed unexpectedly")
	}
	if !strings.Contains(err.Error(), "J1 rubric interactions = 8, want baseline 4") {
		t.Fatalf("planted J1 interaction drift failed for the wrong reason: %v", err)
	}
}

func readJourneyRubricInputs(t *testing.T) ([]byte, []byte) {
	t.Helper()
	baseline, err := os.ReadFile(filepath.Join("ux", "journey-baseline.json"))
	if err != nil {
		t.Fatalf("read journey baseline: %v", err)
	}
	rubric, err := os.ReadFile(filepath.Join("ux", "rubric-results.md"))
	if err != nil {
		t.Fatalf("read journey rubric: %v", err)
	}
	return baseline, rubric
}

func validateJourneyRubricMeasurements(baselineJSON, rubricMarkdown []byte) error {
	var baseline journeyMeasurementBaseline
	if err := json.Unmarshal(baselineJSON, &baseline); err != nil {
		return fmt.Errorf("decode journey baseline: %w", err)
	}
	if len(baseline.Measurements) != 6 {
		return fmt.Errorf("journey baseline has %d measurements, want 6", len(baseline.Measurements))
	}
	rubric, err := parseJourneyRubricMeasurements(string(rubricMarkdown))
	if err != nil {
		return err
	}
	if len(rubric) != len(baseline.Measurements) {
		return fmt.Errorf("journey rubric has %d measurement rows, want %d", len(rubric), len(baseline.Measurements))
	}
	for _, measurement := range baseline.Measurements {
		if measurement.Journey == "" {
			return fmt.Errorf("journey baseline contains an empty journey id")
		}
		if measurement.PointerInteractions != measurement.KeyboardInteractions {
			return fmt.Errorf(
				"%s baseline pointer interactions %d differ from keyboard interactions %d; one rubric interaction cell cannot represent both",
				measurement.Journey,
				measurement.PointerInteractions,
				measurement.KeyboardInteractions,
			)
		}
		got, ok := rubric[measurement.Journey]
		if !ok {
			return fmt.Errorf("journey rubric is missing %s", measurement.Journey)
		}
		if got.Interactions != measurement.PointerInteractions {
			return fmt.Errorf(
				"%s rubric interactions = %d, want baseline %d",
				measurement.Journey,
				got.Interactions,
				measurement.PointerInteractions,
			)
		}
		if got.ContextBreaks != measurement.ContextBreaks {
			return fmt.Errorf(
				"%s rubric context breaks = %d, want baseline %d",
				measurement.Journey,
				got.ContextBreaks,
				measurement.ContextBreaks,
			)
		}
	}
	return nil
}

func parseJourneyRubricMeasurements(markdown string) (map[string]journeyRubricMeasurement, error) {
	const header = "| Journey | Complete outcome"
	lines := strings.Split(markdown, "\n")
	inMeasurementTable := false
	rows := make(map[string]journeyRubricMeasurement, 6)
	for _, line := range lines {
		if strings.HasPrefix(line, header) {
			if inMeasurementTable {
				return nil, fmt.Errorf("journey rubric contains duplicate measurement tables")
			}
			inMeasurementTable = true
			continue
		}
		if !inMeasurementTable {
			continue
		}
		if strings.HasPrefix(line, "| -------") {
			continue
		}
		if !strings.HasPrefix(line, "| J") {
			if len(rows) > 0 {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 6 {
			return nil, fmt.Errorf("journey rubric row has %d cells, want 6: %s", len(cells), line)
		}
		journey := strings.TrimSpace(cells[0])
		if _, duplicate := rows[journey]; duplicate {
			return nil, fmt.Errorf("journey rubric contains duplicate %s row", journey)
		}
		interactions, err := leadingInteger(cells[2])
		if err != nil {
			return nil, fmt.Errorf("%s interactions: %w", journey, err)
		}
		contextBreaks, err := leadingInteger(cells[4])
		if err != nil {
			return nil, fmt.Errorf("%s context breaks: %w", journey, err)
		}
		rows[journey] = journeyRubricMeasurement{
			Interactions:  interactions,
			ContextBreaks: contextBreaks,
		}
	}
	if !inMeasurementTable {
		return nil, fmt.Errorf("journey rubric measurement table is missing")
	}
	return rows, nil
}

func leadingInteger(cell string) (int, error) {
	match := regexp.MustCompile(`^\s*(\d+)\b`).FindStringSubmatch(cell)
	if match == nil {
		return 0, fmt.Errorf("cell %q does not begin with an integer", strings.TrimSpace(cell))
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", match[1], err)
	}
	return value, nil
}
