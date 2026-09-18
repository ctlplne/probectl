// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The verdict-coverage contract (docs/verdict-coverage.md).
//
// A surface that reports what the product OBSERVED must say what it was able to
// observe. Otherwise an empty list means two different things at once — "your
// network is clean" and "nothing here was measuring" — and the reader is given
// the reassuring one for free. The UI depends on this directly: its honest-state
// classifier (web/src/data/classifySurfaceTruth.ts) needs producerRunning to
// distinguish a blocked producer from a real zero, and it cannot invent one.
//
// Two declarations, because there are two ways to be wrong:
//
//	provenance — was anything measuring? (*_running, coverage, methodology,
//	             measurement_fidelity, silent_planes, configured, freshness…)
//	completeness — is this all of it? (truncated, effective_limit, next_cursor…)
//
// Provenance is required of every verdict surface. Completeness is required of
// the ones that apply a bound, because a silently-truncated list presents itself
// as the whole set (DPR-151).
const (
	verdictSurface = "verdict" // reports what was observed
	recordSurface  = "record"  // returns rows the caller or operator created
)

// verdictSurfaceKinds classifies EVERY /v1 operation whose 200 body carries an
// items or summary field. A new one fails this test until someone decides which
// it is — which is the whole point: the classification is the thing that rots,
// not the fields.
var verdictSurfaceKinds = map[string]string{
	// ---- what the product observed --------------------------------------
	"GET /v1/agents":                     verdictSurface,
	"GET /v1/alerts/active":              verdictSurface,
	"GET /v1/alerts/maintenance":         verdictSurface,
	"GET /v1/alerts/{id}/evaluations":    verdictSurface,
	"GET /v1/bgp/events":                 verdictSurface,
	"GET /v1/carbon":                     verdictSurface,
	"GET /v1/changes":                    verdictSurface,
	"GET /v1/compliance":                 verdictSurface,
	"GET /v1/cost/summary":               verdictSurface,
	"GET /v1/coverage/debt":              verdictSurface,
	"GET /v1/coverage/vantages":          verdictSurface,
	"GET /v1/device/collection-outcomes": verdictSurface,
	"GET /v1/device/configs":             verdictSurface,
	"GET /v1/device/identity-conflicts":  verdictSurface,
	"GET /v1/device/metrics":             verdictSurface,
	"GET /v1/device/neighbors":           verdictSurface,
	"GET /v1/device/syslog":              verdictSurface,
	"GET /v1/devices":                    verdictSurface,
	"GET /v1/ebpf/service-map":           verdictSurface,
	"GET /v1/endpoints":                  verdictSurface,
	"GET /v1/flows/anomalies":            verdictSurface,
	"GET /v1/flows/capacity":             verdictSurface,
	"GET /v1/flows/ingest-quality":       verdictSurface,
	"GET /v1/flows/top":                  verdictSurface,
	"GET /v1/incidents":                  verdictSurface,
	"GET /v1/incidents/{id}/changes":     verdictSurface,
	"GET /v1/oncall/status":              verdictSurface,
	"GET /v1/results/history":            verdictSurface,
	"GET /v1/results/latest":             verdictSurface,
	"GET /v1/siem/status":                verdictSurface,
	"GET /v1/slos":                       verdictSurface,
	"GET /v1/tests/{id}/path/history":    verdictSurface,
	"GET /v1/threat/detections":          verdictSurface,
	"GET /v1/tls/posture":                verdictSurface,

	// ---- rows the caller or operator created ----------------------------
	// Nothing was measured, so there is no coverage to declare: an empty list
	// means the tenant has not created any, which is unambiguous.
	"GET /v1/abac/policies":               recordSurface,
	"GET /v1/alerts":                      recordSurface,
	"POST /v1/alerts/maintenance/preview": recordSurface,
	"GET /v1/audit":                       recordSurface,
	"GET /v1/dashboard-report-artifacts":  recordSurface,
	"GET /v1/dashboard-report-schedules":  recordSurface,
	"GET /v1/dashboards":                  recordSurface,
	"GET /v1/directory/roles":             recordSurface,
	"GET /v1/directory/scim-tokens":       recordSurface,
	"GET /v1/directory/users":             recordSurface,
	"GET /v1/hierarchy":                   recordSurface,
	"GET /v1/incidents/{id}/journal":      recordSurface,
	"GET /v1/inventory/views":             recordSurface,
	"GET /v1/isolation/status":            recordSurface,
	"GET /v1/otlp-tokens":                 recordSurface,
	"GET /v1/remediation/proposals":       recordSurface,
	"GET /v1/security/keys":               recordSurface,
	"GET /v1/tests":                       recordSurface,
}

var (
	provenanceField = regexp.MustCompile(
		`_running$|_configured$|^coverage$|^measurement_fidelity$|^methodology$|^silent_planes$|^configured$|^degraded$|^freshness$|^partial_reasons$|^state$|^visibility$`)
	completenessField = regexp.MustCompile(
		`^truncated$|^response_truncated$|^effective_limit$|^next$|^next_cursor$|^limit$|^candidates_truncated$|^entities_truncated$`)
	// A bound the server applies is visible in the spec as one of these.
	boundField = regexp.MustCompile(`^effective_limit$|^limit$|^next$|^next_cursor$|^truncated$`)
)

type openapiSpec struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

type openapiOp struct {
	Responses map[string]struct {
		Content map[string]struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"content"`
	} `json:"responses"`
}

type openapiSchema struct {
	Ref        string                     `json:"$ref"`
	Type       string                     `json:"type"`
	Properties map[string]json.RawMessage `json:"properties"`
	Items      json.RawMessage            `json:"items"`
}

func loadSpec(t *testing.T) openapiSpec {
	t.Helper()
	b, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var spec openapiSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	return spec
}

// resolve follows $ref chains to a concrete schema.
func resolve(spec openapiSpec, raw json.RawMessage, depth int) openapiSchema {
	var sch openapiSchema
	if len(raw) == 0 || depth > 6 {
		return sch
	}
	if err := json.Unmarshal(raw, &sch); err != nil {
		return openapiSchema{}
	}
	if sch.Ref != "" {
		name := sch.Ref[strings.LastIndex(sch.Ref, "/")+1:]
		return resolve(spec, spec.Components.Schemas[name], depth+1)
	}
	return sch
}

func fieldNames(sch openapiSchema) []string {
	out := make([]string, 0, len(sch.Properties))
	for name := range sch.Properties {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// TestEveryObservationSurfaceDeclaresItsCoverage is the gate. It is deliberately
// keyed on the SHAPE of the response (an items/summary envelope) rather than on
// a hand-kept list of interesting routes, so the only way to add an undeclared
// observation surface is to add a row here calling it something it is not.
func TestEveryObservationSurfaceDeclaresItsCoverage(t *testing.T) {
	spec := loadSpec(t)
	seen := map[string]bool{}

	for path, methods := range spec.Paths {
		for method, raw := range methods {
			method = strings.ToUpper(method)
			if method != "GET" && method != "POST" {
				continue
			}
			// A path item also carries non-operation keys such as parameters.
			var op openapiOp
			if err := json.Unmarshal(raw, &op); err != nil {
				continue
			}
			ok200, hasOK := op.Responses["200"]
			if !hasOK {
				continue
			}
			body, hasJSON := ok200.Content["application/json"]
			if !hasJSON {
				continue
			}
			envelope := resolve(spec, body.Schema, 0)
			_, hasItems := envelope.Properties["items"]
			_, hasSummary := envelope.Properties["summary"]
			if !hasItems && !hasSummary {
				continue
			}

			key := method + " " + path
			seen[key] = true
			kind, classified := verdictSurfaceKinds[key]
			if !classified {
				t.Errorf(`%s returns an items/summary envelope but is not classified.
    Add it to verdictSurfaceKinds as %q (it reports what the product observed —
    then its response must declare what was measuring) or %q (it returns rows
    the caller or operator created). See docs/verdict-coverage.md.`,
					key, verdictSurface, recordSurface)
				continue
			}
			if kind != verdictSurface {
				continue
			}

			// Provenance may live on the envelope or on each item — a path
			// round carries its own measurement_fidelity, a TLS posture its own
			// capture and freshness.
			fields := fieldNames(envelope)
			if hasItems {
				item := resolve(spec, envelope.Properties["items"], 0)
				if len(item.Items) > 0 {
					item = resolve(spec, item.Items, 0)
				}
				fields = append(fields, fieldNames(item)...)
				// One level deeper: a path-history row carries its fidelity on
				// the round it wraps, not on the row.
				for _, raw := range item.Properties {
					fields = append(fields, fieldNames(resolve(spec, raw, 0))...)
				}
			}
			if hasSummary {
				fields = append(fields, fieldNames(resolve(spec, envelope.Properties["summary"], 0))...)
			}
			provenance, completeness, bounded := false, false, false
			for _, f := range fields {
				if provenanceField.MatchString(f) {
					provenance = true
				}
				if completenessField.MatchString(f) {
					completeness = true
				}
				if boundField.MatchString(f) {
					bounded = true
				}
			}
			if !provenance {
				t.Errorf(`%s reports what the product observed but never says whether anything WAS observing.
    An empty items array there means both "nothing is wrong" and "nothing was
    measuring", and the reader is handed the reassuring one. Add a producer or
    coverage declaration (a *_running flag, coverage, methodology,
    measurement_fidelity, silent_planes…). Fields present: %v`, key, fields)
			}
			if bounded && !completeness {
				t.Errorf(`%s applies a bound but never says the list is the first page (DPR-151). Fields present: %v`, key, fields)
			}
		}
	}

	// A stale row is its own kind of rot: it lets a deleted route keep a
	// classification that no longer describes anything.
	for key := range verdictSurfaceKinds {
		if !seen[key] {
			t.Errorf("verdictSurfaceKinds classifies %s, which no longer returns an items/summary envelope — remove the row", key)
		}
	}
}
